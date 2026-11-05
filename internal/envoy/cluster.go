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

package envoy

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/projectcontour/contour/internal/dag"
)

// Clustername returns the name of the CDS cluster for this service.
// The name looks like default/kuard/80/92e2d87ab4868b426840.
//
// Note: Cluster name is used to deduplicate clusters.
// When for example two HTTPProxies result in Clusters with equal name, only single cluster will be configured to Envoy.
// Therefore the generated name must contain all relevant fields that make the cluster unique.
func Clustername(cluster *dag.Cluster) string {
	service := cluster.Upstream
	ns := service.Weighted.ServiceNamespace
	name := service.Weighted.ServiceName
	port := strconv.Itoa(int(service.Weighted.ServicePort.Port))

	buf := strconv.Quote(ns) + strconv.Quote(name) + strconv.Quote(port)
	buf += strconv.Quote(cluster.LoadBalancerPolicy)
	if hc := cluster.HTTPHealthCheckPolicy; hc != nil {
		if hc.Timeout > 0 {
			buf += strconv.Quote(hc.Timeout.String())
		}
		if hc.Interval > 0 {
			buf += strconv.Quote(hc.Interval.String())
		}
		if hc.UnhealthyThreshold > 0 {
			buf += strconv.Quote(strconv.Itoa(int(hc.UnhealthyThreshold)))
		}
		if hc.HealthyThreshold > 0 {
			buf += strconv.Quote(strconv.Itoa(int(hc.HealthyThreshold)))
		}
		buf += strconv.Quote(hc.Path)
		buf += strconv.Quote(hc.Host)
		for _, r := range hc.ExpectedStatuses {
			buf += strconv.Quote(fmt.Sprintf("%d-%d", r.Start, r.End))
		}
	}
	if hc := cluster.TCPHealthCheckPolicy; hc != nil {
		buf += strconv.Quote(fmt.Sprintf("tcp %s %s %d %d", hc.Timeout, hc.Interval, hc.UnhealthyThreshold, hc.HealthyThreshold))
	}
	if uv := cluster.UpstreamValidation; uv != nil {
		for _, ca := range uv.CACertificates {
			buf += strconv.Quote(ca.Namespace()) + strconv.Quote(ca.Name())
		}
		buf += "|"
		for _, sn := range uv.SubjectNames {
			buf += strconv.Quote(sn)
		}
	}
	buf += strconv.Quote(cluster.Protocol) + strconv.Quote(cluster.SNI)
	if !cluster.TimeoutPolicy.IdleConnectionTimeout.UseDefault() {
		buf += strconv.Quote(cluster.TimeoutPolicy.IdleConnectionTimeout.Duration().String())
	}
	if cluster.SlowStartConfig != nil {
		buf += strconv.Quote(cluster.SlowStartConfig.String())
	}

	hash := sha256.Sum256([]byte(buf))
	return truncatedPath(ns, name, port) + fmt.Sprintf("/%x", hash[:10])
}

// truncatedPath joins parts with "/", truncating each to 15 characters.
func truncatedPath(parts ...string) string {
	for i, p := range parts {
		parts[i] = p[:min(len(p), 15)]
	}
	return strings.Join(parts, "/")
}

// AltStatName generates an alternative stat name for the service
// using format ns_name_port
func AltStatName(service *dag.Service) string {
	parts := []string{service.Weighted.ServiceNamespace, service.Weighted.ServiceName, strconv.Itoa(int(service.Weighted.ServicePort.Port))}
	return strings.Join(parts, "_")
}

// AnyPositive indicates if any of the values provided are greater than zero.
func AnyPositive(first uint32, rest ...uint32) bool {
	if first > 0 {
		return true
	}
	for _, v := range rest {
		if v > 0 {
			return true
		}
	}
	return false
}

// DNSNameClusterName returns the name of the CDS cluster for this DNS name based upstream (e.g. JWKS endpoint).
// The name looks like dnsname/https/idp.example.com/443/92e2d87ab4868b426840.
//
// Note: Cluster name is used to deduplicate clusters.
// When for example two HTTPProxies result in Clusters with equal name, only single cluster will be configured to Envoy.
// Therefore the generated name must contain all relevant fields that make the cluster unique.
func DNSNameClusterName(cluster *dag.DNSNameCluster) string {
	// Values are quoted to keep their boundaries unambiguous, otherwise e.g. CA secrets
	// tenant-a/idp-ca and tenant-ai/dp-ca would both become "tenant-aidp-ca".
	buf := strconv.Quote(cluster.Scheme) + strconv.Quote(cluster.Address) + strconv.Quote(strconv.Itoa(cluster.Port))
	buf += strconv.Quote(cluster.DNSLookupFamily)

	if uv := cluster.UpstreamValidation; uv != nil {
		for _, ca := range uv.CACertificates {
			if ca != nil {
				buf += strconv.Quote(ca.Namespace()) + strconv.Quote(ca.Name())
			}
		}
		for _, sn := range uv.SubjectNames {
			buf += strconv.Quote(sn)
		}
	}

	// Unlike in Clustername(), the name does not include the namespace, so a user in
	// another namespace could use the same JWKS URI and try subjectNames until the hash
	// matches. The hash must be long enough to make that infeasible.
	hash := sha256.Sum256([]byte(buf))

	// Scheme, address and port are added as plain text to make the name readable.
	return strings.Join([]string{"dnsname", cluster.Scheme, cluster.Address, strconv.Itoa(cluster.Port), fmt.Sprintf("%x", hash[:10])}, "/")
}
