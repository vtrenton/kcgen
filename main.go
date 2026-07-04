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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type kubeuser struct {
	Username   string `yaml:"username"`
	Server     string `yaml:"server"`
	Clientcert string `yaml:"clientcert"`
	Clientkey  string `yaml:"clientkey"`
}

func (kuser kubeuser) genKubeConfig(kubeclient *kubernetes.Clientset) (*api.Config, error) {
	ctx := context.Background()

	// Retrieve the CA certificate from the kube-root-ca.crt ConfigMap in the kube-system namespace
	configMap, err := kubeclient.CoreV1().ConfigMaps("kube-system").Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
	if err != nil {
		log.Printf("Failed to retrieve ConfigMap containing CA certificate: %v", err)
		return nil, err
	}

	caCert, ok := configMap.Data["ca.crt"]
	if !ok {
		log.Printf("CA certificate not found in ConfigMap kube-root-ca.crt")
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
			kcname: {
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

	log.Printf("Successfully generated kubeconfig for %s\n", kcname)
	return kubeconfig, nil
}

// This function actually tought me about named return values.
// I can use this so I know which []byte return is which
// by looking at the function signature. Very cool!
func (kuser kubeuser) generateKeyandCSR() (privKeyPEM, csrPEM []byte, err error) {
	// ECDSA P-256 is what kubeadm uses for its certs so it's good enough for this
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// After generating the private key lets build a CSR template
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: kuser.Username,
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

func (kuser kubeuser) submitCSR(ctx context.Context, kubeclient *kubernetes.Clientset, csr []byte) (*certificatesv1.CertificateSigningRequest, error) {
	// We need to name the CSR but to avoid naming collsions when running back to back
	// we append a random string to the end of the name.
	var suffix [4]byte
	rand.Read(suffix[:])
	csrName := fmt.Sprintf("kcgen-%s-%x", kuser.Username, suffix)

	// lets build the kubernetes CSR Object
	kubeCSR := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csr,
			SignerName: "kubernetes.io/kube-apiserver-client",
			Usages: []certificatesv1.KeyUseage{
				certificatesv1.UsageClientAuth,
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageKeyEncipherment,
			},
		},
	}

	created, err := kubeclient.CertificatesV1().CertificateSigningRequests().Create(ctx, kubeCSR, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to submit CSR %s: %w", csrName, err)
	}

	return created, nil
}

func genkubeclient() (*kubernetes.Clientset, string, error) {
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)

	restConfig, err := kubeconfig.ClientConfig()
	if err != nil {
		return fmt.Errorf("loading kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("creating clientset: %w", err)
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
	kubeclient, kuser.Server, err := genkubeclient()
	if err != nil {
		return err
	}

	// Generate a client certificate and CSR
	privKey, csr, err := kuser.generateKeyandCSR()
	if err != nil {
		return err
	}
	log.Println("Generated the private key and csr")

	// The kubernetes client requires a context definition for stuff like timeouts
	// We're really not going to use it but need to define it to fufil the contracts.
	ctx := context.Background()

	// Submit the CSR
	kubeCSR, err := submitCSR(ctx, kubeclient, csr)
	if err != nil {
		return err
	}
	log.Println("Created CSR")

	// Approve the CSR

	// Append signed cert to kuser object
	kuser.Clientcert = getSignedCert()

	// generate the kubeconfig
	kubeconfig, err := kuser.genKubeConfig(kubeclient)
	if err != nil {
		log.Fatalf("Failed to generate kubeconfig: %v", err)
	}

	// Convert kubeconfig to YAML format
	kubeconfigYAML, err := clientcmd.Write(*kubeconfig)
	if err != nil {
		log.Fatalf("Failed to convert kubeconfig to YAML: %v", err)
	}

	// Define the file path to write the kubeconfig file
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube", fmt.Sprintf("%s-kubeconfig.yaml", kuser.Username))

	// Write the YAML data to a file
	err = os.WriteFile(kubeconfigPath, kubeconfigYAML, 0644)
	if err != nil {
		log.Fatalf("Failed to write kubeconfig to file: %v", err)
	}

	log.Printf("Successfully wrote kubeconfig to %s", kubeconfigPath)
}
