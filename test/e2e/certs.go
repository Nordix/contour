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

package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"
	"github.com/tsaarni/certyaml"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcontour/contour/internal/dag"
)

// Certs provides helpers for creating certificates
// and related resources.
type Certs struct {
	client        client.Client
	retryInterval time.Duration
	retryTimeout  time.Duration
	t             ginkgo.GinkgoTInterface
	// issuers stores in-memory CA credentials keyed by "ns/name" for signing child certs.
	issuers map[string]*certyaml.Certificate
}

// CreateSelfSignedCert creates a self-signed server certificate as a TLS Secret.
// It returns a cleanup function that deletes the Secret.
func (c *Certs) CreateSelfSignedCert(ns, name, secretName, dnsName string) func() {
	cert := certyaml.Certificate{
		Subject:         "CN=" + name,
		SubjectAltNames: []string{"DNS:" + dnsName},
	}

	secret := &core_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: ns,
			Name:      secretName,
		},
		Type: core_v1.SecretTypeTLS,
		Data: map[string][]byte{
			core_v1.TLSCertKey:       cert.CertPEM(),
			core_v1.TLSPrivateKeyKey: cert.KeyPEM(),
			dag.CACertificateKey:     cert.CertPEM(),
		},
	}
	require.NoError(c.t, c.client.Create(context.TODO(), secret))

	return func() {
		require.NoError(c.t, c.client.Delete(context.TODO(), secret))
	}
}

// GetTLSCertificate returns a tls.Certificate containing the data in the specified
// secret and optional CA certificate. The secret must have the "tls.crt" and "tls.key" keys,
// and "ca.crt" if CA certificate is also provided.
func (c *Certs) GetTLSCertificate(secretNamespace, secretName string) (tls.Certificate, *x509.CertPool) {
	secret := &core_v1.Secret{}
	require.NoError(c.t, c.client.Get(context.TODO(), client.ObjectKey{Namespace: secretNamespace, Name: secretName}, secret))

	cert, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	require.NoError(c.t, err)

	var caBundle *x509.CertPool
	ca, ok := secret.Data["ca.crt"]
	if ok {
		caBundle = x509.NewCertPool()
		caBundle.AppendCertsFromPEM(ca)
	}

	return cert, caBundle
}

// CreateCA creates a root CA and stores it as an opaque Secret with cert and key.
func (c *Certs) CreateCA(ns, name string) func() {
	ca := certyaml.Certificate{
		Subject: "CN=" + name,
	}

	if c.issuers == nil {
		c.issuers = make(map[string]*certyaml.Certificate)
	}
	c.issuers[ns+"/"+name] = &ca

	caSecret := &core_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Type: core_v1.SecretTypeOpaque,
		Data: map[string][]byte{
			core_v1.TLSCertKey:       ca.CertPEM(),
			core_v1.TLSPrivateKeyKey: ca.KeyPEM(),
		},
	}
	require.NoError(c.t, c.client.Create(context.TODO(), caSecret))

	return func() {
		require.NoError(c.t, c.client.Delete(context.TODO(), caSecret))
	}
}

// CreateCert creates an end-entity TLS Secret signed by the given CA created via CreateCA.
// Optionally accepts DNS names to set SubjectAltNames.
func (c *Certs) CreateCert(ns, name, issuer string, dnsNames ...string) func() {
	ca, ok := c.issuers[ns+"/"+issuer]
	require.True(c.t, ok, "issuer %s/%s not found; call CreateCA first", ns, issuer)

	// Issue end-entity certificate signed by CA.
	endEntity := certyaml.Certificate{
		Subject:         "CN=" + name,
		Issuer:          ca,
		SubjectAltNames: nil,
	}
	if len(dnsNames) > 0 {
		sans := make([]string, 0, len(dnsNames))
		for _, d := range dnsNames {
			sans = append(sans, "DNS:"+d)
		}
		endEntity.SubjectAltNames = sans
	}

	secret := &core_v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Type: core_v1.SecretTypeTLS,
		Data: map[string][]byte{
			core_v1.TLSCertKey:       endEntity.CertPEM(),
			core_v1.TLSPrivateKeyKey: endEntity.KeyPEM(),
			dag.CACertificateKey:     ca.CertPEM(),
		},
	}
	require.NoError(c.t, c.client.Create(context.TODO(), secret))

	return func() {
		require.NoError(c.t, c.client.Delete(context.TODO(), secret))
	}
}
