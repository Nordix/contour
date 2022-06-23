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

package featuretests

// kubernetes helpers

import (
	v1 "k8s.io/api/core/v1"
	networking_v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func IngressBackend(svc *v1.Service) *networking_v1.IngressBackend {
	return &networking_v1.IngressBackend{
		Service: &networking_v1.IngressServiceBackend{
			Name: svc.Name,
			Port: networking_v1.ServiceBackendPort{
				Number: svc.Spec.Ports[0].Port,
			},
		},
	}
}

// nolint:revive
const (
	// CERTIFICATE generated by https://www.selfsignedcertificate.com
	CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJAOv27DGlF3qdMA0GCSqGSIb3DQEBBQUAMCUxIzAhBgNV
BAMMGmJvcmluZy13b3puaWFrLmV4YW1wbGUuY29tMB4XDTE5MTIwNTAxMzQzM1oX
DTI5MTIwMjAxMzQzM1owJTEjMCEGA1UEAwwaYm9yaW5nLXdvem5pYWsuZXhhbXBs
ZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbgwFwfbikZxPb
NYidPuNJoexq5W9fJrB/3jqsWox8pfess0bw/EL/VcEUqlrcuo40Md0MxApPuoPj
eZCOZYhrA2XgcVTMnq61vusnuvmeG/qcrd5apSOoopSo2pmmI1rsJ1AVpheA+eR6
uoWVILK8uYtPmcOQAoCU/E6iZYDLZ0AEiU16kz/cGfWx9lBukd+LQ+ZRQnLDiEI/
4hRmrZrEdJoDglzIgJVI+c8OfwbLq5eRMY2fYnxqm/1BJhqjDBc4Q8ufYgfOwobu
JdVoSgiFy7wyH0GxMk4LRR6yJXLs1yjaihLERbjzlStvFVl4yidpE6Bi0amKW8HT
Qxgk7iRRAgMBAAGjUDBOMB0GA1UdDgQWBBTLcIMeWLFiL2waFL6FPomNZR7gFDAf
BgNVHSMEGDAWgBTLcIMeWLFiL2waFL6FPomNZR7gFDAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA4IBAQBQLWokaWuFeSWLpxxaBX6aatgKAKNUSqDWNzM9zVMH
xJVDywWJT3pwq7JUXujVS/c9mzCPJEsn7OQPihQECRq09l/nBK0kn9I1X6X1SMtD
OJbpEWfQQxgstdgeC6pxrZRanF5a7EWO0pFSfjuM1ABjsdExaG3C8+wgEqOjHFDS
NaW826GOFf/uMOnavpG6QePECAtJVpLAZPw6Rah6cAZrYUUezM/Tg+8JUhYUS20F
STZG5knGQIe6kksWGkJUhMu8xLdH2HKtUVAkDu7jITy2WZbg0O/Pxe30b4qyt29Y
813p8G+7188EFDBGNihYYVJ+GJ/d/WPoptSHJOfShtbk
-----END CERTIFICATE-----`

	RSA_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA24MBcH24pGcT2zWInT7jSaHsauVvXyawf946rFqMfKX3rLNG
8PxC/1XBFKpa3LqONDHdDMQKT7qD43mQjmWIawNl4HFUzJ6utb7rJ7r5nhv6nK3e
WqUjqKKUqNqZpiNa7CdQFaYXgPnkerqFlSCyvLmLT5nDkAKAlPxOomWAy2dABIlN
epM/3Bn1sfZQbpHfi0PmUUJyw4hCP+IUZq2axHSaA4JcyICVSPnPDn8Gy6uXkTGN
n2J8apv9QSYaowwXOEPLn2IHzsKG7iXVaEoIhcu8Mh9BsTJOC0UesiVy7Nco2ooS
xEW485UrbxVZeMonaROgYtGpilvB00MYJO4kUQIDAQABAoIBAF5L671gNIZjRVNg
rtwl3MuPxJizEOHGJAH5/Ch4CWuufDPzG6GALGO1eekfuUKi3V2sofHO8UMIs4lv
elrBYRXfcs80wCHadODcL/Z0SrDSAhl2U1OLJ0NU/BmBNon5HCDgTnXOUMB2GOFj
6OiEEGQkLKU4P5tIh+X4cOswQWCeoVjW0JVgni20hi3LJNTxSNYeU5VFvPKtoBLl
8nFqF3ky+bqYfS6H6qM/mO+XL0NQ2wjMteyUeDXcVGfsf7Ir21SUw3zGaeBJl55B
6BrUgfxVOKuxkw2bwxmu8HX+CxlMMMzaRt+5URFbfOaMgXzjpikrxdeFAAGeu0m4
bidUR5UCgYEA8lRGqYfowoOCrV8Ksn8nM0Z9PlnmKM5d9mQ875sm/SYLO43h+s0D
R4VWmLzaGyi0m0036lxIthDfbbGWSjmNrgQ0YIS7ilmBPMUKKYzXgDoiI76aJBTz
UMpWutb+VYimPPorLKcxNb3BjR3QHx7vCRS2gV5izV0djtMkKc53OXsCgYEA5+Uz
A7cmO8gHyxlW6SA3+wMH6VKP5ABTkDmKfRF3NCv4UHNn4TtlNuS1D3ZMNXWgCtz6
qJ/bRTAqseBIX15pzR/MvyNmHRUN3A2Ba6vB2pJux+ZyQjxn3Z+gisjX+eN3LvTU
YpcJNi0HSuV57n4AAk5YPO5iMEFw95vfBn3MMaMCgYEAnFwyqAsQ7gmLVTDBJ0GS
Wqx9/bBmKShXSreM9hIHi0pz7v5ytLB6EDkCElWw6dtPBfJCRQ88v3WNpSr0TXpr
Z8BAx5J9rBxqnnqJPxwopQ1dn/DJZsS55wRYCADXZPtiQHAvUYWj5AhHjjWRZ7M/
C3348OqlF9ugSdsFN5CIL2cCgYEAqt5lop03XOFdbLe1JH4LAbgQAkpFoDjlWeYs
N0/BR/4GMDF5H6sGP1ZyW3xNVy7eyGJfiBSSGv8M1phue2c0CmMeGNDakx9KYRTK
gi3C32z6l+0jz852sgTG5Lxs98I1tbHNNQAZV4QCVZuVJrhNBWX4+pykWO4/cRO3
WC8lYIUCgYBmmN4z0MR2YWoRvN3lYey3bRGAvsSU6ouiFo40UZdZaRXc1sA3oc+5
6Di3f8eOIhM5IekOBoaTBf90V8seB6Nw+/jzAViG1HDI7k0ZOoApDuFS6NYk1/bU
dk98FvYdyAjjgNsxXCyx7vIgYU3OgVNgvFsFubX/Uk66fcfCpPBMLg==
-----END RSA PRIVATE KEY-----`

	CRL = `-----BEGIN X509 CRL-----
MIHlMIGMAgEBMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMTEGNsaWVudC1yb290LWNh
LTEXDTIyMDYyMTA5NDQ0NVoXDTIyMDYyODA5NDQ0NVowGzAZAggW+pmWu/XnExcN
MjIwNjIxMDk0NDQ1WqAjMCEwHwYDVR0jBBgwFoAULRlmjBtfjbzwV2WeO9Vj5pWO
h5gwCgYIKoZIzj0EAwIDSAAwRQIhANVFCqByuASAcbz6ovyvi5KCtPfNjHjxVaNT
x69LFPN1AiA5pF5rqHy1FBctZBTW+3LTEEX35j3p1++zcNu8oHMO/w==
-----END X509 CRL-----`
)

func Secretdata(cert, key string) map[string][]byte {
	return map[string][]byte{
		v1.TLSCertKey:       []byte(cert),
		v1.TLSPrivateKeyKey: []byte(key),
	}
}

func Endpoints(ns, name string, subsets ...v1.EndpointSubset) *v1.Endpoints {
	return &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Subsets: subsets,
	}
}

func Ports(eps ...v1.EndpointPort) []v1.EndpointPort {
	return eps
}

func Port(name string, port int32) v1.EndpointPort {
	return v1.EndpointPort{
		Name:     name,
		Port:     port,
		Protocol: "TCP",
	}
}

func Addresses(ips ...string) []v1.EndpointAddress {
	var addrs []v1.EndpointAddress
	for _, ip := range ips {
		addrs = append(addrs, v1.EndpointAddress{IP: ip})
	}
	return addrs
}
