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

//go:build e2e

package httpproxy

import (
	"context"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	contour_v1 "github.com/projectcontour/contour/apis/projectcontour/v1"
	"github.com/projectcontour/contour/internal/dag"
	"github.com/projectcontour/contour/test/e2e"
)

func testBackendTLSProtocolVersion(namespace, protocolVersion string) {
	Specify("backend connection uses configured TLS version", func() {
		// Backend server cert and CA cert.
		ca := certyaml.Certificate{Subject: "CN=ca-cert"}
		server := certyaml.Certificate{Subject: "CN=echo-secure", Issuer: &ca, SubjectAltNames: []string{"DNS:echo-secure"}}
		require.NoError(f.T(), f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Namespace: namespace, Name: "backend-server-cert"},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       server.CertPEM(),
				core_v1.TLSPrivateKeyKey: server.KeyPEM(),
				dag.CACertificateKey:     ca.CertPEM(), // Include CA for using the secret for downstream validation.
			},
		}))
		f.Fixtures.EchoSecure.Deploy(namespace, "echo-secure", nil)

		p := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "backend-tls",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "backend-tls.projectcontour.io",
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-secure",
								Port: 443,
								UpstreamValidation: &contour_v1.UpstreamValidation{
									CACertificate: "backend-server-cert",
									SubjectName:   "echo-secure",
								},
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(p, e2e.HTTPProxyValid))

		type responseTLSDetails struct {
			TLS struct {
				Version string
			}
		}

		// Send HTTP request, we will check backend connection was over HTTPS.
		res, ok := f.HTTP.RequestUntil(&e2e.HTTPRequestOpts{
			Host:      p.Spec.VirtualHost.Fqdn,
			Condition: e2e.HasStatusCode(200),
		})
		require.NotNil(f.T(), res, "request never succeeded")
		require.Truef(f.T(), ok, "expected 200 response code, got %d", res.StatusCode)

		// Get cert presented to backend app.
		tlsInfo := new(responseTLSDetails)
		require.NoError(f.T(), json.Unmarshal(res.Body, tlsInfo))
		assert.Equal(f.T(), tlsInfo.TLS.Version, protocolVersion)
	})
}
