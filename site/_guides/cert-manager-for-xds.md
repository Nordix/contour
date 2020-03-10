---
**NOTE**
WORK-IN-PROGRESS: For now, this document just has commands to use cert-manager for issuing certificates for xDS gRPC TLS connection.  It is not ready for public consumption.
---



## Steps to follow

Install cert-manager by running

```bash
kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.13.1/cert-manager.yaml

# ensure that installation has succeeded and pods are running
kubectl -n cert-manager get pods
```

Create namespace for Contour


```bash
kubectl create namespace projectcontour
```


Create CA

```bash
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1alpha2
kind: Issuer
metadata:
  name: self-signed-issuer
  namespace: projectcontour
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: cluster-ca
  namespace: projectcontour
spec:
  secretName: cluster-ca-keypair
  commonName: cluster-ca
  duration: 87600h # 10 years
  isCA: true
  usages:
    - client auth
    - server auth
  issuerRef:
    name: self-signed-issuer
    kind: Issuer
---
apiVersion: cert-manager.io/v1alpha2
kind: Issuer
metadata:
  name: ca-issuer
  namespace: projectcontour
spec:
  ca:
    secretName: cluster-ca-keypair
EOF
```


Create certificate and key for Contour and Envoy

```bash
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: contour
  namespace: projectcontour
spec:
  secretName: contourcert
  commonName: contour
  dnsNames:
    - contour
    - contour.projectcontour
    - contour.projectcontour.svc.cluster.local
  duration: 1h
  isCA: false
  issuerRef:
    name: ca-issuer
    kind: Issuer
---
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: envoy
  namespace: projectcontour
spec:
  secretName: envoycert
  commonName: envoy
  duration: 1h
  isCA: false
  usages:
    - client auth
  issuerRef:
    name: ca-issuer
    kind: Issuer
EOF
```

Install Contour

```bash
kustomize build examples/cert-manager | kubectl apply -f -
```

Here the kustomize step removes use of `contour certgen` and removes the Kubernetes Secret volume mounts for cacert.
In case of cert-manger the end-entity certificate and key, and ca certifica is stored in single secret.
In case of certgen there is two separate secrets.
