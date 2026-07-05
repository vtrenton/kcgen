# kcgen

`kcgen` automates the creation of a Kubernetes client kubeconfig for a named user. It handles every manual step — key generation, CSR creation, Kubernetes CSR submission and approval, certificate retrieval, and kubeconfig assembly — in a single command.

## What it does

### 1. ECDSA Private Key Generation

Manually you would run something like:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out user.key
```

`kcgen` generates an ECDSA P-256 private key in memory using Go's `crypto/ecdsa` package (the same curve kubeadm uses for its own certificates), then PEM-encodes it in PKCS#8 format.

---

### 2. X.509 CSR Generation

Manually:

```bash
openssl req -new -key user.key -out user.csr -subj "/CN=<username>"
```

`kcgen` builds an `x509.CertificateRequest` template with the username set as the `CommonName`, signs it with the generated private key, and PEM-encodes the result — all without touching disk.

---

### 3. Kubernetes CertificateSigningRequest Submission

Manually you would write a YAML manifest and apply it:

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: kcgen-<username>-<random>
spec:
  request: <base64-encoded CSR>
  signerName: kubernetes.io/kube-apiserver-client
  usages:
    - client auth
```

```bash
kubectl apply -f csr.yaml
```

`kcgen` submits this object directly via the Kubernetes API using `client-go`. The CSR name includes a random 4-byte hex suffix to avoid collisions when running back-to-back.

---

### 4. CSR Approval

Manually:

```bash
kubectl certificate approve kcgen-<username>-<random>
```

Under the hood `kubectl certificate approve` patches the CSR's status conditions — `kcgen` does the same thing: it appends a `CertificateApproved` condition to the CSR's `.status.conditions` and calls `UpdateApproval()` on the Kubernetes API.

---

### 5. Signed Certificate Retrieval

After approval the Kubernetes controller manager signs the certificate and writes it back to the CSR object's `.status.certificate` field. There is no kubectl equivalent here — you would poll manually or write a watch loop.

`kcgen` polls the CSR object every 2 seconds for up to 30 seconds until the signed certificate appears.

---

### 6. Kubeconfig Assembly

Manually you would:

1. Retrieve the cluster CA from the `kube-root-ca.crt` ConfigMap in `kube-system`:
   ```bash
   kubectl get configmap kube-root-ca.crt -n kube-system -o jsonpath='{.data.ca\.crt}'
   ```
2. Base64-encode the CA cert, client cert, and client key.
3. Hand-write or template a kubeconfig YAML combining all of them with the server URL.

`kcgen` fetches the CA automatically using the active kubeconfig's credentials, then assembles a complete kubeconfig struct using `client-go`'s `api.Config` type and serializes it to YAML via `clientcmd.Write`.

The output file is written to:

```
~/.kube/<username>-kubeconfig.yaml
```

with `0600` permissions so only the owner can read it.

---

## Prerequisites

- Go 1.21+
- A valid kubeconfig already in place (`~/.kube/config` or `$KUBECONFIG`)
- Cluster permissions to create and approve `CertificateSigningRequest` objects

## Build

```bash
go build -o kcgen .
```

## Usage

```bash
# Create a kubeconfig for a specific user
./kcgen <username>

# Defaults to "example-user" if no argument is given
./kcgen
```

The generated kubeconfig will be at `~/.kube/<username>-kubeconfig.yaml`.

## Notes

- The private key never touches disk until the final kubeconfig write.
- The Kubernetes CSR object is left on the cluster after completion. Clean it up with:
  ```bash
  kubectl delete csr kcgen-<username>-<suffix>
  ```
- This tool requires permission to approve CSRs. In most clusters that means running as a cluster-admin or having a custom RBAC role that grants `update` on `certificatesigningrequests/approval`.
