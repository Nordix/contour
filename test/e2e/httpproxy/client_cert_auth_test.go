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
	"crypto/tls"
	"strings"

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

func testClientCertAuth(namespace string) {
	Specify("client requests can be authenticated", func() {
		t := f.T()

		// Create two CAs.
		caPC := certyaml.Certificate{Subject: "CN=projectcontour"}
		caNPC := certyaml.Certificate{Subject: "CN=notprojectcontour"}

		f.Fixtures.Echo.Deploy(namespace, "echo-no-auth")

		// Server certificate for echo-no-auth.
		echoNoAuth := certyaml.Certificate{Subject: "CN=echo-no-auth", Issuer: &caPC, SubjectAltNames: []string{"DNS:echo-no-auth.projectcontour.io"}}
		require.NoError(t, f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Name: "echo-no-auth", Namespace: namespace},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       echoNoAuth.CertPEM(),
				core_v1.TLSPrivateKeyKey: echoNoAuth.KeyPEM(),
			},
		}))

		f.Fixtures.Echo.Deploy(namespace, "echo-with-auth")

		echoWithAuth := certyaml.Certificate{Subject: "CN=echo-with-auth", Issuer: &caPC, SubjectAltNames: []string{"DNS:echo-with-auth.projectcontour.io"}}
		require.NoError(t, f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Name: "echo-with-auth", Namespace: namespace},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       echoWithAuth.CertPEM(),
				core_v1.TLSPrivateKeyKey: echoWithAuth.KeyPEM(),
				dag.CACertificateKey:     caPC.CertPEM(), // Include CA for using the secret for downstream validation.

			},
		}))

		f.Fixtures.Echo.Deploy(namespace, "echo-with-auth-skip-verify")

		echoWithAuthSkipVerify := certyaml.Certificate{Subject: "CN=echo-with-auth-skip-verify", Issuer: &caPC, SubjectAltNames: []string{"DNS:echo-with-auth-skip-verify.projectcontour.io"}}
		require.NoError(t, f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Name: "echo-with-auth-skip-verify", Namespace: namespace},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       echoWithAuthSkipVerify.CertPEM(),
				core_v1.TLSPrivateKeyKey: echoWithAuthSkipVerify.KeyPEM(),
			},
		}))

		f.Fixtures.Echo.Deploy(namespace, "echo-with-auth-skip-verify-with-ca")

		echoWithAuthSkipVerifyWithCA := certyaml.Certificate{Subject: "CN=echo-with-auth-skip-verify-with-ca", Issuer: &caPC, SubjectAltNames: []string{"DNS:echo-with-auth-skip-verify-with-ca.projectcontour.io"}}
		require.NoError(t, f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Name: "echo-with-auth-skip-verify-with-ca", Namespace: namespace},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       echoWithAuthSkipVerifyWithCA.CertPEM(),
				core_v1.TLSPrivateKeyKey: echoWithAuthSkipVerifyWithCA.KeyPEM(),
			},
		}))

		f.Fixtures.Echo.Deploy(namespace, "echo-with-optional-auth")

		echoWithOptional := certyaml.Certificate{Subject: "CN=echo-with-optional-auth", Issuer: &caPC, SubjectAltNames: []string{"DNS:echo-with-optional-auth.projectcontour.io"}}
		require.NoError(t, f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Name: "echo-with-optional-auth", Namespace: namespace},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       echoWithOptional.CertPEM(),
				core_v1.TLSPrivateKeyKey: echoWithOptional.KeyPEM(),
			},
		}))

		f.Fixtures.Echo.Deploy(namespace, "echo-with-optional-auth-no-ca")

		echoWithOptionalNoCA := certyaml.Certificate{Subject: "CN=echo-with-optional-auth-no-ca", Issuer: &caPC, SubjectAltNames: []string{"DNS:echo-with-optional-auth-no-ca.projectcontour.io"}}
		require.NoError(t, f.Client.Create(context.TODO(), &core_v1.Secret{
			ObjectMeta: meta_v1.ObjectMeta{Name: "echo-with-optional-auth-no-ca", Namespace: namespace},
			Type:       core_v1.SecretTypeTLS,
			Data: map[string][]byte{
				core_v1.TLSCertKey:       echoWithOptionalNoCA.CertPEM(),
				core_v1.TLSPrivateKeyKey: echoWithOptionalNoCA.KeyPEM(),
			},
		}))

		// This proxy does not require client certificate auth.
		noAuthProxy := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "echo-no-auth",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "echo-no-auth.projectcontour.io",
					TLS: &contour_v1.TLS{
						SecretName: "echo-no-auth",
					},
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-no-auth",
								Port: 80,
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(noAuthProxy, e2e.HTTPProxyValid))

		// This proxy requires client certificate auth.
		authProxy := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "echo-with-auth",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "echo-with-auth.projectcontour.io",
					TLS: &contour_v1.TLS{
						SecretName: "echo-with-auth",
						ClientValidation: &contour_v1.DownstreamValidation{
							CACertificate: "echo-with-auth",
						},
					},
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-with-auth",
								Port: 80,
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(authProxy, e2e.HTTPProxyValid))

		// This proxy does not verify client certs.
		authSkipVerifyProxy := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "echo-with-auth-skip-verify",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "echo-with-auth-skip-verify.projectcontour.io",
					TLS: &contour_v1.TLS{
						SecretName: "echo-with-auth-skip-verify",
						ClientValidation: &contour_v1.DownstreamValidation{
							SkipClientCertValidation: true,
						},
					},
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-with-auth-skip-verify",
								Port: 80,
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(authSkipVerifyProxy, e2e.HTTPProxyValid))

		// This proxy requires a client certificate but does not verify it.
		authSkipVerifyWithCAProxy := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "echo-with-auth-skip-verify-with-ca",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "echo-with-auth-skip-verify-with-ca.projectcontour.io",
					TLS: &contour_v1.TLS{
						SecretName: "echo-with-auth-skip-verify-with-ca",
						ClientValidation: &contour_v1.DownstreamValidation{
							SkipClientCertValidation: true,
							CACertificate:            "echo-with-auth",
						},
					},
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-with-auth-skip-verify-with-ca",
								Port: 80,
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(authSkipVerifyWithCAProxy, e2e.HTTPProxyValid))

		// This proxy requests a client certificate but only verifies it if sent.
		optionalAuthProxy := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "echo-with-optional-auth",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "echo-with-optional-auth.projectcontour.io",
					TLS: &contour_v1.TLS{
						SecretName: "echo-with-optional-auth",
						ClientValidation: &contour_v1.DownstreamValidation{
							OptionalClientCertificate: true,
							CACertificate:             "echo-with-auth",
						},
					},
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-with-optional-auth",
								Port: 80,
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(optionalAuthProxy, e2e.HTTPProxyValid))

		// This proxy requests a client certificate but doesn't verify it if sent.
		optionalAuthNoCAProxy := &contour_v1.HTTPProxy{
			ObjectMeta: meta_v1.ObjectMeta{
				Namespace: namespace,
				Name:      "echo-with-optional-auth-no-ca",
			},
			Spec: contour_v1.HTTPProxySpec{
				VirtualHost: &contour_v1.VirtualHost{
					Fqdn: "echo-with-optional-auth-no-ca.projectcontour.io",
					TLS: &contour_v1.TLS{
						SecretName: "echo-with-optional-auth-no-ca",
						ClientValidation: &contour_v1.DownstreamValidation{
							OptionalClientCertificate: true,
							SkipClientCertValidation:  true,
						},
					},
				},
				Routes: []contour_v1.Route{
					{
						Services: []contour_v1.Service{
							{
								Name: "echo-with-optional-auth-no-ca",
								Port: 80,
							},
						},
					},
				},
			},
		}
		require.True(f.T(), f.CreateHTTPProxyAndWaitFor(optionalAuthNoCAProxy, e2e.HTTPProxyValid))

		// Client certificate.
		client := certyaml.Certificate{Subject: "CN=client", Issuer: &caPC}
		validClientCert, _ := client.TLSCertificate()

		// Invalid client certificate.
		badclient := certyaml.Certificate{Subject: "CN=badclient", Issuer: &caNPC}
		invalidClientCert, _ := badclient.TLSCertificate()

		cases := map[string]struct {
			host       string
			clientCert *tls.Certificate
			wantErr    string
		}{
			"echo-no-auth without a client cert should succeed": {
				host:       noAuthProxy.Spec.VirtualHost.Fqdn,
				clientCert: nil,
				wantErr:    "",
			},
			"echo-no-auth with echo-client-cert should succeed": {
				host:       noAuthProxy.Spec.VirtualHost.Fqdn,
				clientCert: &validClientCert,
				wantErr:    "",
			},
			"echo-no-auth with echo-client-cert-invalid should succeed": {
				host:       noAuthProxy.Spec.VirtualHost.Fqdn,
				clientCert: &invalidClientCert,
				wantErr:    "",
			},

			"echo-with-auth without a client cert should error": {
				host:       authProxy.Spec.VirtualHost.Fqdn,
				clientCert: nil,
				wantErr:    "tls: certificate required",
			},
			"echo-with-auth with echo-client-cert should succeed": {
				host:       authProxy.Spec.VirtualHost.Fqdn,
				clientCert: &validClientCert,
				wantErr:    "",
			},
			"echo-with-auth with echo-client-cert-invalid should error": {
				host:       authProxy.Spec.VirtualHost.Fqdn,
				clientCert: &invalidClientCert,
				wantErr:    "tls: unknown certificate authority",
			},

			"echo-with-auth-skip-verify without a client cert should succeed": {
				host:       authSkipVerifyProxy.Spec.VirtualHost.Fqdn,
				clientCert: nil,
				wantErr:    "",
			},
			"echo-with-auth-skip-verify with echo-client-cert should succeed": {
				host:       authSkipVerifyProxy.Spec.VirtualHost.Fqdn,
				clientCert: &validClientCert,
				wantErr:    "",
			},
			"echo-with-auth-skip-verify with echo-client-cert-invalid should succeed": {
				host:       authSkipVerifyProxy.Spec.VirtualHost.Fqdn,
				clientCert: &invalidClientCert,
				wantErr:    "",
			},

			"echo-with-auth-skip-verify-with-ca without a client cert should error": {
				host:       authSkipVerifyWithCAProxy.Spec.VirtualHost.Fqdn,
				clientCert: nil,
				wantErr:    "tls: certificate required",
			},
			"echo-with-auth-skip-verify-with-ca with echo-client-cert should succeed": {
				host:       authSkipVerifyWithCAProxy.Spec.VirtualHost.Fqdn,
				clientCert: &validClientCert,
				wantErr:    "",
			},
			"echo-with-auth-skip-verify-with-ca with echo-client-cert-invalid should succeed": {
				host:       authSkipVerifyWithCAProxy.Spec.VirtualHost.Fqdn,
				clientCert: &invalidClientCert,
				wantErr:    "",
			},

			"echo-with-optional-auth without a client cert should succeed": {
				host:       optionalAuthProxy.Spec.VirtualHost.Fqdn,
				clientCert: nil,
				wantErr:    "",
			},
			"echo-with-optional-auth with echo-client-cert should succeed": {
				host:       optionalAuthProxy.Spec.VirtualHost.Fqdn,
				clientCert: &validClientCert,
				wantErr:    "",
			},
			"echo-with-optional-auth with echo-client-cert-invalid should error": {
				host:       optionalAuthProxy.Spec.VirtualHost.Fqdn,
				clientCert: &invalidClientCert,
				wantErr:    "tls: unknown certificate authority",
			},
			"echo-with-optional-auth-no-ca without a client cert should succeed": {
				host:       optionalAuthNoCAProxy.Spec.VirtualHost.Fqdn,
				clientCert: nil,
				wantErr:    "",
			},
			"echo-with-optional-auth-no-ca with echo-client-cert should succeed": {
				host:       optionalAuthNoCAProxy.Spec.VirtualHost.Fqdn,
				clientCert: &validClientCert,
				wantErr:    "",
			},
			"echo-with-optional-auth-no-ca with echo-client-cert-invalid should succeed": {
				host:       optionalAuthNoCAProxy.Spec.VirtualHost.Fqdn,
				clientCert: &invalidClientCert,
				wantErr:    "",
			},
		}

		for name, tc := range cases {
			t.Logf("Running test case %s", name)
			opts := &e2e.HTTPSRequestOpts{
				Host: tc.host,
			}
			if tc.clientCert != nil {
				opts.TLSConfigOpts = append(opts.TLSConfigOpts, optUseClientCert(tc.clientCert))
			}

			switch {
			case len(tc.wantErr) == 0:
				opts.Condition = e2e.HasStatusCode(200)
				res, ok := f.HTTP.SecureRequestUntil(opts)
				require.NotNil(t, res, "expected 200 response code, request was never successful")
				assert.Truef(t, ok, "expected 200 response code, got %d", res.StatusCode)
			default:
				// Since we're expecting an error making the request
				// itself, SecureRequestUntil won't work since that
				// assumes an HTTP response is gotten.
				assert.Eventually(t, func() bool {
					_, err := f.HTTP.SecureRequest(opts)
					if err == nil {
						return false
					}

					return strings.Contains(err.Error(), tc.wantErr)
				}, f.RetryTimeout, f.RetryInterval)
			}
		}
	})
}

func optUseClientCert(cert *tls.Certificate) func(*tls.Config) {
	return func(c *tls.Config) {
		// Use c.GetClientCertificate rather than setting c.Certificates so the
		// client cert specified is always presented, regardless of the request
		// details from the server.
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}
}
