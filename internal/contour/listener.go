// Copyright © 2019 VMware
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

package contour

import (
	"sort"
	"sync"
	"time"

	envoy_api_v2_auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	envoy_api_v2_listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	envoy_api_v2_accesslog "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/pkg/cache"
	"github.com/golang/protobuf/proto"
	"github.com/projectcontour/contour/internal/dag"
	"github.com/projectcontour/contour/internal/envoy"
)

const (
	ENVOY_HTTP_LISTENER            = "ingress_http"
	ENVOY_HTTPS_LISTENER           = "ingress_https"
	DEFAULT_HTTP_ACCESS_LOG        = "/dev/stdout"
	DEFAULT_HTTP_LISTENER_ADDRESS  = "0.0.0.0"
	DEFAULT_HTTP_LISTENER_PORT     = 8080
	DEFAULT_HTTPS_ACCESS_LOG       = "/dev/stdout"
	DEFAULT_HTTPS_LISTENER_ADDRESS = DEFAULT_HTTP_LISTENER_ADDRESS
	DEFAULT_HTTPS_LISTENER_PORT    = 8443
	DEFAULT_ACCESS_LOG_TYPE        = "envoy"
)

// ListenerVisitorConfig holds configuration parameters for visitListeners.
type ListenerVisitorConfig struct {
	// Envoy's HTTP (non TLS) listener address.
	// If not set, defaults to DEFAULT_HTTP_LISTENER_ADDRESS.
	HTTPAddress string

	// Envoy's HTTP (non TLS) listener port.
	// If not set, defaults to DEFAULT_HTTP_LISTENER_PORT.
	HTTPPort int

	// Envoy's HTTP (non TLS) access log path.
	// If not set, defaults to DEFAULT_HTTP_ACCESS_LOG.
	HTTPAccessLog string

	// Envoy's HTTPS (TLS) listener address.
	// If not set, defaults to DEFAULT_HTTPS_LISTENER_ADDRESS.
	HTTPSAddress string

	// Envoy's HTTPS (TLS) listener port.
	// If not set, defaults to DEFAULT_HTTPS_LISTENER_PORT.
	HTTPSPort int

	// Envoy's HTTPS (TLS) access log path.
	// If not set, defaults to DEFAULT_HTTPS_ACCESS_LOG.
	HTTPSAccessLog string

	// UseProxyProto configures all listeners to expect a PROXY
	// V1 or V2 preamble.
	// If not set, defaults to false.
	UseProxyProto bool

	// MinimumProtocolVersion defines the min tls protocol version to be used
	MinimumProtocolVersion envoy_api_v2_auth.TlsParameters_TlsProtocol

	// AccessLogType defines if Envoy logs should be output as Envoy's default or JSON.
	// Valid values: 'envoy', 'json'
	// If not set, defaults to 'envoy'
	AccessLogType string

	// AccessLogFields sets the fields that should be shown in JSON logs.
	// Valid entries are the keys from internal/envoy/accesslog.go:jsonheaders
	// Defaults to a particular set of fields.
	AccessLogFields []string

	// RequestTimeout configures the request_timeout for all Connection Managers.
	RequestTimeout time.Duration
}

// httpAddress returns the port for the HTTP (non TLS)
// listener or DEFAULT_HTTP_LISTENER_ADDRESS if not configured.
func (lvc *ListenerVisitorConfig) httpAddress() string {
	if lvc.HTTPAddress != "" {
		return lvc.HTTPAddress
	}
	return DEFAULT_HTTP_LISTENER_ADDRESS
}

// httpPort returns the port for the HTTP (non TLS)
// listener or DEFAULT_HTTP_LISTENER_PORT if not configured.
func (lvc *ListenerVisitorConfig) httpPort() int {
	if lvc.HTTPPort != 0 {
		return lvc.HTTPPort
	}
	return DEFAULT_HTTP_LISTENER_PORT
}

// httpAccessLog returns the access log for the HTTP (non TLS)
// listener or DEFAULT_HTTP_ACCESS_LOG if not configured.
func (lvc *ListenerVisitorConfig) httpAccessLog() string {
	if lvc.HTTPAccessLog != "" {
		return lvc.HTTPAccessLog
	}
	return DEFAULT_HTTP_ACCESS_LOG
}

// httpsAddress returns the port for the HTTPS (TLS)
// listener or DEFAULT_HTTPS_LISTENER_ADDRESS if not configured.
func (lvc *ListenerVisitorConfig) httpsAddress() string {
	if lvc.HTTPSAddress != "" {
		return lvc.HTTPSAddress
	}
	return DEFAULT_HTTPS_LISTENER_ADDRESS
}

// httpsPort returns the port for the HTTPS (TLS) listener
// or DEFAULT_HTTPS_LISTENER_PORT if not configured.
func (lvc *ListenerVisitorConfig) httpsPort() int {
	if lvc.HTTPSPort != 0 {
		return lvc.HTTPSPort
	}
	return DEFAULT_HTTPS_LISTENER_PORT
}

// httpsAccessLog returns the access log for the HTTPS (TLS)
// listener or DEFAULT_HTTPS_ACCESS_LOG if not configured.
func (lvc *ListenerVisitorConfig) httpsAccessLog() string {
	if lvc.HTTPSAccessLog != "" {
		return lvc.HTTPSAccessLog
	}
	return DEFAULT_HTTPS_ACCESS_LOG
}

// accesslogType returns the access log type that should be configured
// across all listener types or DEFAULT_ACCESS_LOG_TYPE if not configured.
func (lvc *ListenerVisitorConfig) accesslogType() string {
	if lvc.AccessLogType != "" {
		return lvc.AccessLogType
	}
	return DEFAULT_ACCESS_LOG_TYPE
}

// accesslogFields returns the access log fields that should be configured
// for Envoy, or a default set if not configured.
func (lvc *ListenerVisitorConfig) accesslogFields() []string {
	if lvc.AccessLogFields != nil {
		return lvc.AccessLogFields
	}
	return envoy.DefaultFields
}

func (lvc *ListenerVisitorConfig) newInsecureAccessLog() []*envoy_api_v2_accesslog.AccessLog {
	switch lvc.accesslogType() {
	case "json":
		return envoy.FileAccessLogJSON(lvc.httpAccessLog(), lvc.accesslogFields())
	default:
		return envoy.FileAccessLogEnvoy(lvc.httpAccessLog())
	}
}

func (lvc *ListenerVisitorConfig) newSecureAccessLog() []*envoy_api_v2_accesslog.AccessLog {
	switch lvc.accesslogType() {
	case "json":
		return envoy.FileAccessLogJSON(lvc.httpsAccessLog(), lvc.accesslogFields())
	default:
		return envoy.FileAccessLogEnvoy(lvc.httpsAccessLog())
	}
}

// requestTimeout sets any durations in lvc.RequestTimeout <0 to 0 so that Envoy ends up with a positive duration.
// for the request_timeout value we are passing, there are only two valid values:
// 0 - disabled
// >0 duration - the timeout.
// The value may be unset, but we always set it to 0.
func (lvc *ListenerVisitorConfig) requestTimeout() time.Duration {

	if lvc.RequestTimeout < 0 {
		return 0
	}
	return lvc.RequestTimeout
}

// minProtocolVersion returns the requested minimum TLS protocol
// version or envoy_api_v2_auth.TlsParameters_TLSv1_1 if not configured {
func (lvc *ListenerVisitorConfig) minProtoVersion() envoy_api_v2_auth.TlsParameters_TlsProtocol {
	if lvc.MinimumProtocolVersion > envoy_api_v2_auth.TlsParameters_TLSv1_1 {
		return lvc.MinimumProtocolVersion
	}
	return envoy_api_v2_auth.TlsParameters_TLSv1_1
}

// ListenerCache manages the contents of the gRPC LDS cache.
type ListenerCache struct {
	mu           sync.Mutex
	values       map[string]*v2.Listener
	staticValues map[string]*v2.Listener
	Cond
}

// NewListenerCache returns an instance of a ListenerCache
func NewListenerCache(address string, port int) ListenerCache {
	stats := envoy.StatsListener(address, port)
	return ListenerCache{
		staticValues: map[string]*v2.Listener{
			stats.Name: stats,
		},
	}
}

// Update replaces the contents of the cache with the supplied map.
func (c *ListenerCache) Update(v map[string]*v2.Listener) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values = v
	c.Cond.Notify()
}

// Contents returns a copy of the cache's contents.
func (c *ListenerCache) Contents() []proto.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	var values []proto.Message
	for _, v := range c.values {
		values = append(values, v)
	}
	for _, v := range c.staticValues {
		values = append(values, v)
	}
	sort.Stable(listenersByName(values))
	return values
}

// Query returns the proto.Messages in the ListenerCache that match
// a slice of strings
func (c *ListenerCache) Query(names []string) []proto.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	var values []proto.Message
	for _, n := range names {
		v, ok := c.values[n]
		if !ok {
			v, ok = c.staticValues[n]
			if !ok {
				// if the listener is not registered in
				// dynamic or static values then skip it
				// as there is no way to return a blank
				// listener because the listener address
				// field is required.
				continue
			}
		}
		values = append(values, v)
	}
	sort.Stable(listenersByName(values))
	return values
}

type listenersByName []proto.Message

func (l listenersByName) Len() int      { return len(l) }
func (l listenersByName) Swap(i, j int) { l[i], l[j] = l[j], l[i] }
func (l listenersByName) Less(i, j int) bool {
	return l[i].(*v2.Listener).Name < l[j].(*v2.Listener).Name
}

func (*ListenerCache) TypeURL() string { return cache.ListenerType }

type listenerVisitor struct {
	*ListenerVisitorConfig

	listeners map[string]*v2.Listener
	http      bool // at least one dag.VirtualHost encountered
}

func visitListeners(root dag.Vertex, lvc *ListenerVisitorConfig) map[string]*v2.Listener {
	lv := listenerVisitor{
		ListenerVisitorConfig: lvc,
		listeners: map[string]*v2.Listener{
			ENVOY_HTTPS_LISTENER: envoy.Listener(
				ENVOY_HTTPS_LISTENER,
				lvc.httpsAddress(), lvc.httpsPort(),
				secureProxyProtocol(lvc.UseProxyProto),
			),
		},
	}
	lv.visit(root)

	// add a listener if there are vhosts bound to http.
	if lv.http {
		lv.listeners[ENVOY_HTTP_LISTENER] = envoy.Listener(
			ENVOY_HTTP_LISTENER,
			lvc.httpAddress(), lvc.httpPort(),
			proxyProtocol(lvc.UseProxyProto),
			envoy.HTTPConnectionManager(ENVOY_HTTP_LISTENER, lvc.newInsecureAccessLog(), lvc.requestTimeout()),
		)

	}

	// remove the https listener if there are no vhosts bound to it.
	if len(lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains) == 0 {
		delete(lv.listeners, ENVOY_HTTPS_LISTENER)
	} else {
		// there's some https listeners, we need to sort the filter chains
		// to ensure that the LDS entries are identical.
		sort.SliceStable(lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains,
			func(i, j int) bool {
				// The ServerNames field will only ever have a single entry
				// in our FilterChain config, so it's okay to only sort
				// on the first slice entry.
				return lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains[i].FilterChainMatch.ServerNames[0] < lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains[j].FilterChainMatch.ServerNames[0]
			})
	}

	return lv.listeners
}

func proxyProtocol(useProxy bool) []*envoy_api_v2_listener.ListenerFilter {
	if useProxy {
		return envoy.ListenerFilters(
			envoy.ProxyProtocol(),
		)
	}
	return nil
}

func secureProxyProtocol(useProxy bool) []*envoy_api_v2_listener.ListenerFilter {
	return append(proxyProtocol(useProxy), envoy.TLSInspector())
}

func (v *listenerVisitor) visit(vertex dag.Vertex) {
	max := func(a, b envoy_api_v2_auth.TlsParameters_TlsProtocol) envoy_api_v2_auth.TlsParameters_TlsProtocol {
		if a > b {
			return a
		}
		return b
	}

	switch vh := vertex.(type) {
	case *dag.VirtualHost:
		// we only create on http listener so record the fact
		// that we need to then double back at the end and add
		// the listener properly.
		v.http = true
	case *dag.SecureVirtualHost:
		filters := envoy.Filters(
			envoy.HTTPConnectionManager(ENVOY_HTTPS_LISTENER, v.ListenerVisitorConfig.newSecureAccessLog(), v.ListenerVisitorConfig.requestTimeout()),
		)
		alpnProtos := []string{"h2", "http/1.1"}
		if vh.TCPProxy != nil {
			filters = envoy.Filters(
				envoy.TCPProxy(ENVOY_HTTPS_LISTENER, vh.TCPProxy, v.ListenerVisitorConfig.newSecureAccessLog()),
			)
			alpnProtos = nil // do not offer ALPN
		}

		fc := envoy.FilterChainTLS(
			vh.VirtualHost.Name,
			envoy.DownstreamTLSContext(
				vh.Secret,
				max(v.ListenerVisitorConfig.minProtoVersion(), vh.MinProtoVersion), // Choose the higher of the configured or requested tls version.
				vh.DownstreamValidation,
				alpnProtos...),
			filters,
		)

		v.listeners[ENVOY_HTTPS_LISTENER].FilterChains = append(v.listeners[ENVOY_HTTPS_LISTENER].FilterChains, fc)
	default:
		// recurse
		vertex.Visit(v.visit)
	}
}
