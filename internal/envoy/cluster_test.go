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
	"testing"

	"github.com/stretchr/testify/assert"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcontour/contour/internal/dag"
)

func TestTruncatedPath(t *testing.T) {
	tests := map[string]struct {
		parts []string
		want  string
	}{
		"short":       {parts: []string{"default", "kuard", "80"}, want: "default/kuard/80"},
		"exactly 15":  {parts: []string{"fifteen-chars-x", "kuard"}, want: "fifteen-chars-x/kuard"},
		"long":        {parts: []string{"long-namespace-name", "long-service-name", "8080"}, want: "long-namespace-/long-service-na/8080"},
		"single part": {parts: []string{"kuard"}, want: "kuard"},
		"no parts":    {parts: nil, want: ""},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, truncatedPath(tc.parts...))
		})
	}
}

func TestAnyPositive(t *testing.T) {
	assert.False(t, AnyPositive(0))
	assert.True(t, AnyPositive(1))
	assert.False(t, AnyPositive(0, 0))
	assert.True(t, AnyPositive(1, 0))
	assert.True(t, AnyPositive(0, 1))
}

func TestClusternameUnique(t *testing.T) {
	svc := func(ns, name string) *dag.Service {
		return &dag.Service{Weighted: dag.WeightedService{ServiceNamespace: ns, ServiceName: name, ServicePort: core_v1.ServicePort{Port: 8080}}}
	}
	ca := func(ns string) []*dag.Secret {
		return []*dag.Secret{{Object: &core_v1.Secret{ObjectMeta: meta_v1.ObjectMeta{Namespace: ns, Name: "ca"}}}}
	}
	kuard := svc("default", "kuard")

	tests := map[string][2]*dag.Cluster{
		"long names in different namespaces": {
			{Upstream: svc("long-namespace-name-number-one", "long-service-name-one")},
			{Upstream: svc("long-namespace-name-number-two", "long-service-name-two")},
		},
		"health check host": {
			{Upstream: kuard, HTTPHealthCheckPolicy: &dag.HTTPHealthCheckPolicy{Host: "a.internal"}},
			{Upstream: kuard, HTTPHealthCheckPolicy: &dag.HTTPHealthCheckPolicy{Host: "b.internal"}},
		},
		"health check expected statuses": {
			{Upstream: kuard, HTTPHealthCheckPolicy: &dag.HTTPHealthCheckPolicy{}},
			{Upstream: kuard, HTTPHealthCheckPolicy: &dag.HTTPHealthCheckPolicy{ExpectedStatuses: []dag.HTTPStatusRange{{Start: 200, End: 300}}}},
		},
		"health check thresholds 1, 23 and 12, 3": {
			{Upstream: kuard, HTTPHealthCheckPolicy: &dag.HTTPHealthCheckPolicy{UnhealthyThreshold: 1, HealthyThreshold: 23}},
			{Upstream: kuard, HTTPHealthCheckPolicy: &dag.HTTPHealthCheckPolicy{UnhealthyThreshold: 12, HealthyThreshold: 3}},
		},
		"tcp health check": {
			{Upstream: kuard},
			{Upstream: kuard, TCPHealthCheckPolicy: &dag.TCPHealthCheckPolicy{}},
		},
		"CA namespace": {
			{Upstream: kuard, UpstreamValidation: &dag.PeerValidationContext{CACertificates: ca("default")}},
			{Upstream: kuard, UpstreamValidation: &dag.PeerValidationContext{CACertificates: ca("other")}},
		},
		"second subject name": {
			{Upstream: kuard, UpstreamValidation: &dag.PeerValidationContext{SubjectNames: []string{"a"}}},
			{Upstream: kuard, UpstreamValidation: &dag.PeerValidationContext{SubjectNames: []string{"a", "b"}}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NotEqual(t, Clustername(tc[0]), Clustername(tc[1]))
		})
	}

	assert.Regexp(t, `^long-namespace-/long-service-na/8080/[0-9a-f]{20}$`, Clustername(tests["long names in different namespaces"][0]))
}

func TestSecretnameUnique(t *testing.T) {
	secret := func(ns, name string) *dag.Secret {
		return &dag.Secret{Object: &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Namespace: ns, Name: name},
			Data:       map[string][]byte{core_v1.TLSCertKey: []byte("cert")},
		}}
	}
	assert.NotEqual(t,
		Secretname(secret("long-namespace-name-number-one", "long-secret-name-one")),
		Secretname(secret("long-namespace-name-number-two", "long-secret-name-two")))
	assert.Regexp(t, `^default/secret/[0-9a-f]{20}$`, Secretname(secret("default", "secret")))
}
