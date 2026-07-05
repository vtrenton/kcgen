package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	coreV1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/homedir"
)

type kubeuser struct {
	Username   string `yaml:"username"`
	Server     string `yaml:"server"`
	Clientcert []byte `yaml:"clientcert"`
	Clientkey  []byte `yaml:"clientkey"`
}

func (kuser kubeuser) genKubeConfig(kubeclient *kubernetes.Clientset) (*api.Config, error) {
	ctx := context.Background()

	// Retrieve the CA certificate from the kube-root-ca.crt ConfigMap in the kube-system namespace
	configMap, err := kubeclient.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve ConfigMap containing CA certificate: %v", err)
	}

	caCert, ok := configMap.Data["ca.crt"]
	if !ok {
		return nil, fmt.Errorf("CA certificate not found in ConfigMap kube-root-ca.crt")
	}

	// Construct the kubeconfig object using the Client certificate, Client key and CA certificate
	kubeconfig := &api.Config{
		Clusters: map[string]*api.Cluster{
			"kubernetes": {
				Server:                   kuser.Server,
				CertificateAuthorityData: []byte(caCert),
			},
		},
		AuthInfos: map[string]*api.AuthInfo{
			kuser.Username: {
				ClientKeyData:         kuser.Clientkey,
				ClientCertificateData: kuser.Clientcert,
			},
		},
		Contexts: map[string]*api.Context{
			"kubernetes": {
				Cluster:  "kubernetes",
				AuthInfo: kuser.Username,
			},
		},
		CurrentContext: "kubernetes",
	}

	log.Printf("Successfully generated kubeconfig for %s\n", kuser.Username)
	return kubeconfig, nil
}

// This function actually tought me about named return values.
// I can use this so I know which []byte return is which
// by looking at the function signature. Very cool!
func generateKeyandCSR(username string) (privKeyPEM, csrPEM []byte, err error) {
	// ECDSA P-256 is what kubeadm uses for its certs so it's good enough for this
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// After generating the private key lets build a CSR template
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: username,
		},
	}

	// Now let's encode the template a private key into DER format
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Now let's encode the private key into DER as well
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Lastly, lets take these DERs and convert them to PEMs that can be used
	// Then return them
	// note the lack of walrus assignment here. These are the "named return values"
	privKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	return privKeyPEM, csrPEM, nil
}

func submitCSR(ctx context.Context, kubeclient *kubernetes.Clientset, username string, csr []byte) (*certificatesv1.CertificateSigningRequest, error) {
	// We need to name the CSR but to avoid naming collsions when running back to back
	// we append a random string to the end of the name.
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	csrName := fmt.Sprintf("kcgen-%s-%x", username, suffix)

	// lets build the kubernetes CSR Object
	// for the usages client auth is all we should need
	kubeCSR := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csr,
			SignerName: "kubernetes.io/kube-apiserver-client",
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageClientAuth,
			},
		},
	}

	// Now we use the create method to deploy the CSR Object to the cluster
	created, err := kubeclient.CertificatesV1().CertificateSigningRequests().Create(ctx, kubeCSR, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to submit CSR %s: %w", csrName, err)
	}

	// Return the created CSR Object in the cluster
	// The reason we need to return the full object
	// is because the approval method requires the object
	// Still less costly than a full network call
	return created, nil
}

func approveCSR(ctx context.Context, kubeclient *kubernetes.Clientset, csr *certificatesv1.CertificateSigningRequest) error {
	// In order to approve the CSR we need to add an approval to the status failed
	// This is the method kubectl approve uses as well.
	// Also useful if we want to build an approval operator in the future
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:           certificatesv1.CertificateApproved,
		Status:         coreV1.ConditionTrue,
		Reason:         "KCGenApproved",
		Message:        "Approved by kcgen",
		LastUpdateTime: metav1.Now(),
	})
	// The UpdateApproval() method is what will actually update the object on the cluster for us.
	// We don't need anything returned once its posted but error handling is important.
	_, err := kubeclient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to approve CSR %s: %w", csr.Name, err)
	}
	return nil
}

func getSignedCert(ctx context.Context, kubeclient *kubernetes.Clientset, csrName string) ([]byte, error) {
	// The cert might not be ready right away so polling it over a deadline
	// will give us a way to retry and have a timeout
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		csr, err := kubeclient.CertificatesV1().CertificateSigningRequests().Get(ctx, csrName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get CSR %s, %w", csrName, err)
		}
		// Happy path
		if len(csr.Status.Certificate) > 0 {
			return csr.Status.Certificate, nil
		}
		// retry backoff
		time.Sleep(2 * time.Second)
	}
	// if we breach the 30 second threshhold
	return nil, fmt.Errorf("timed out waiting for certificate from CSR %s", csrName)
}

// small helper method to get the active kubeconfig and create a usable go object for k8s client functions
func genkubeclient() (*kubernetes.Clientset, string, error) {

	// This will look for the kubeconfig in the standard manner
	// KUBECONFIG env OR .kube/config path.
	// this also allows for override flags such as --context for example
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)

	// The restconfig is an intermediate object that allows us to query some useful information
	// out of the existing kubeconfig
	restConfig, err := kubeconfig.ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("loading kubeconfig: %w", err)
	}

	// Finally this is the clientset that will be useful for our methods going forward.
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, "", fmt.Errorf("creating clientset: %w", err)
	}

	return clientset, restConfig.Host, nil
}

func main() {
	// set up our user object
	var kuser kubeuser

	// set the "username" for the kubeuser from stdin
	if len(os.Args) == 2 {
		kuser.Username = os.Args[1]
	} else {
		fmt.Println("username not passed in. defaulting to 'example-user'...")
		kuser.Username = "example-user"
	}

	// get the client config (to access k8s cluster) and set the server value
	kubeclient, server, err := genkubeclient()
	if err != nil {
		log.Fatal(err)
	}
	kuser.Server = server

	// Generate a client certificate and CSR
	privKey, csr, err := generateKeyandCSR(kuser.Username)
	if err != nil {
		log.Fatal(err)
	}
	kuser.Clientkey = privKey
	log.Println("Generated the private key and csr")

	// The kubernetes client requires a context definition for stuff like timeouts
	// We're really not going to use it but need to define it to fufil the contracts.
	ctx := context.Background()

	// Submit the CSR
	kubeCSR, err := submitCSR(ctx, kubeclient, kuser.Username, csr)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Created CSR")

	// Approve the CSR
	err = approveCSR(ctx, kubeclient, kubeCSR)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Added approval to CSR")

	// Append signed cert to kuser object
	kuser.Clientcert, err = getSignedCert(ctx, kubeclient, kubeCSR.Name)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Signed Cert obtained from the Kubernetes CSR Object")

	// generate the kubeconfig
	kubeconfig, err := kuser.genKubeConfig(kubeclient)
	if err != nil {
		log.Fatal(err)
	}

	// Convert kubeconfig to YAML format
	kubeconfigYAML, err := clientcmd.Write(*kubeconfig)
	if err != nil {
		log.Fatalf("Failed to convert kubeconfig to YAML: %v", err)
	}

	// Define the file path to write the kubeconfig file
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", fmt.Sprintf("%s-kubeconfig.yaml", kuser.Username))

	// Write the YAML data to a file
	// Most OS's will set this to 644 mode by default
	// 600 will restrict read and write only to the user owner
	err = os.WriteFile(kubeconfigPath, kubeconfigYAML, 0600)
	if err != nil {
		log.Fatalf("Failed to write kubeconfig to file: %v", err)
	}

	log.Printf("Successfully wrote kubeconfig to %s", kubeconfigPath)
}
