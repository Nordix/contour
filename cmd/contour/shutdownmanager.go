// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	xdscache_v3 "github.com/projectcontour/contour/internal/xdscache/v3"
	"github.com/prometheus/common/expfmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

const (
	prometheusURLFormat      = "http://localhost:%d/stats/prometheus"
	healthcheckFailURLFormat = "http://localhost:%d/healthcheck/fail"
	prometheusStat           = "envoy_http_downstream_cx_active"
)

func prometheusLabels() []string {
	return []string{xdscache_v3.ENVOY_HTTP_LISTENER, xdscache_v3.ENVOY_HTTPS_LISTENER}
}

type shutdownmanagerContext struct {
	// httpServePort defines what port the shutdown-manager listens on
	httpServePort int

	// checkInterval defines time delay between polling Envoy for open connections
	checkInterval time.Duration

	// checkDelay defines time to wait before polling Envoy for open connections
	checkDelay time.Duration

	// drainDelay defines time to wait before draining Envoy connections
	drainDelay time.Duration

	// minOpenConnections defines the minimum amount of connections
	// that can be open when polling for active connections in Envoy
	minOpenConnections int

	// adminPort defines the port for our envoy pod, being configurable through --admin-port flag
	adminPort int

	// maxDrainTime defined the number of seconds to wait until minimum open connections is reached
	maxDrainTime time.Duration

	logrus.FieldLogger
}

func newShutdownManagerContext() *shutdownmanagerContext {
	// Set defaults for parameters which are then overridden via flags, ENV, or ConfigFile
	return &shutdownmanagerContext{
		httpServePort:      8090,
		checkInterval:      5 * time.Second,
		checkDelay:         60 * time.Second,
		drainDelay:         0,
		minOpenConnections: 0,
		adminPort:          9001,
		maxDrainTime:       200 * time.Second,
	}
}

// healthzHandler handles the /healthz endpoint which is used for the shutdown-manager's liveness probe.
func (s *shutdownmanagerContext) healthzHandler(w http.ResponseWriter, r *http.Request) {
	http.StatusText(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		s.WithField("context", "healthzHandler").Error(err)
	}
}

// shutdownReadyHandler handles the /shutdown endpoint which is used by kubelet to determine if it can terminate Envoy.
// It is called from Envoy container's preStop hook and it blocks pod shutdown until Envoy is able to drain connections.
// Once enough connections have drained based upon min-open threshold, HTTP response will be returned and kubelet will
// proceed with pod shutdown.
func (s *shutdownmanagerContext) shutdownReadyHandler(w http.ResponseWriter, r *http.Request) {
	l := s.WithField("context", "shutdownReadyHandler")
	ctx := r.Context()

	l.Infof("waiting %s before draining connections", s.drainDelay)
	time.Sleep(s.drainDelay)

	// Send shutdown signal to Envoy to start draining connections
	s.Infof("failing envoy healthchecks")

	// Retry any failures to shutdownEnvoy(s.adminPort) in a Backoff time window
	// doing 4 total attempts, multiplying the Duration by the Factor
	// for each iteration.
	err := retry.OnError(wait.Backoff{
		Steps:    4,
		Duration: 200 * time.Millisecond,
		Factor:   5.0,
		Jitter:   0.1,
	}, func(err error) bool {
		// Always retry any error.
		return true
	}, func() error {
		s.Infof("attempting to shutdown")
		return shutdownEnvoy(s.adminPort)
	})
	if err != nil {
		// May be conflict if max retries were hit, or may be something unrelated
		// like permissions or a network error
		l.Errorf("error sending envoy healthcheck fail after 4 attempts: %v", err)
	}

	l.Infof("waiting %s before polling for draining connections", s.checkDelay)
	time.Sleep(s.checkDelay)
	maxDrainTimeout := time.After(s.maxDrainTime)

	for {
		openConnections, err := getOpenConnections(s.adminPort)
		if err != nil {
			s.Error(err)
		} else {
			if openConnections <= s.minOpenConnections {
				l.WithField("open_connections", openConnections).
					WithField("min_connections", s.minOpenConnections).
					Info("min number of open connections found, sending HTTP response to proceed with shutdown")
				return
			}
			l.
				WithField("open_connections", openConnections).
				WithField("min_connections", s.minOpenConnections).
				Info("polled open connections")
		}
		select {
		case <-time.After(s.checkInterval):
		case <-maxDrainTimeout:
			l.Infof("maximum drain time reached, sending HTTP response to proceed with shutdown")
			return
		case <-ctx.Done():
			l.Infof("client request cancelled")
			return
		}
	}

}

// shutdownEnvoy sends a POST request to /healthcheck/fail to tell Envoy to start draining connections
func shutdownEnvoy(adminPort int) error {
	healthcheckFailURL := fmt.Sprintf(healthcheckFailURLFormat, adminPort)
	/* #nosec */
	resp, err := http.Post(healthcheckFailURL, "", nil)
	if err != nil {
		return fmt.Errorf("creating healthcheck fail POST request failed: %s", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST for %q returned HTTP status %s", healthcheckFailURL, resp.Status)
	}
	return nil
}

// getOpenConnections parses a http request to a prometheus endpoint returning the sum of values found
func getOpenConnections(adminPort int) (int, error) {
	prometheusURL := fmt.Sprintf(prometheusURLFormat, adminPort)
	// Make request to Envoy Prometheus endpoint
	/* #nosec */
	resp, err := http.Get(prometheusURL)
	if err != nil {
		return -1, fmt.Errorf("creating metrics GET request failed: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("GET for %q returned HTTP status %s", prometheusURL, resp.Status)
	}

	// Parse Prometheus listener stats for open connections
	return parseOpenConnections(resp.Body)
}

// parseOpenConnections returns the sum of open connections from a Prometheus HTTP request
func parseOpenConnections(stats io.Reader) (int, error) {
	var parser expfmt.TextParser
	openConnections := 0

	if stats == nil {
		return -1, fmt.Errorf("stats input was nil")
	}

	// Parse Prometheus http response
	metricFamilies, err := parser.TextToMetricFamilies(stats)
	if err != nil {
		return -1, fmt.Errorf("parsing Prometheus text format failed: %v", err)
	}

	// Validate stat exists in output
	if _, ok := metricFamilies[prometheusStat]; !ok {
		return -1, fmt.Errorf("error finding Prometheus stat %q in the request result", prometheusStat)
	}

	// Look up open connections value
	for _, metrics := range metricFamilies[prometheusStat].Metric {
		for _, labels := range metrics.Label {
			for _, item := range prometheusLabels() {
				if item == labels.GetValue() {
					openConnections += int(metrics.Gauge.GetValue())
				}
			}
		}
	}
	return openConnections, nil
}

func doShutdownManager(config *shutdownmanagerContext) {

	config.Info("started envoy shutdown manager")
	defer config.Info("stopped")

	http.HandleFunc("/healthz", config.healthzHandler)
	http.HandleFunc("/shutdown", config.shutdownReadyHandler)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.httpServePort), nil))
}

// registerShutdownManager registers the envoy shutdown-manager sub-command and flags
func registerShutdownManager(cmd *kingpin.CmdClause, log logrus.FieldLogger) (*kingpin.CmdClause, *shutdownmanagerContext) {
	ctx := newShutdownManagerContext()
	ctx.FieldLogger = log.WithField("context", "shutdown-manager")

	shutdownmgr := cmd.Command("shutdown-manager", "Start envoy shutdown-manager.")
	shutdownmgr.Flag("serve-port", "Port to serve the http server on.").IntVar(&ctx.httpServePort)
	shutdownmgr.Flag("admin-port", "Envoy admin interface port.").IntVar(&ctx.adminPort)
	shutdownmgr.Flag("check-interval", "Time to poll Envoy for open connections.").DurationVar(&ctx.checkInterval)
	shutdownmgr.Flag("check-delay", "Time to wait before polling Envoy for open connections.").Default("60s").DurationVar(&ctx.checkDelay)
	shutdownmgr.Flag("drain-delay", "Time to wait before draining Envoy connections.").Default("0s").DurationVar(&ctx.drainDelay)
	shutdownmgr.Flag("min-open-connections", "Min number of open connections when polling Envoy.").IntVar(&ctx.minOpenConnections)

	return shutdownmgr, ctx
}
