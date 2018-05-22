// Copyright 2017 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	cert "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	api "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	extended "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

var (
	additionalDNSNames string
	secretName         string
	clusterDomain      string
	hostname           string
	namespace          string
	serviceName        string
)

func main() {
	flag.StringVar(&additionalDNSNames, "additional-dnsnames", "", "additional dns names; comma separated")
	flag.StringVar(&secretName, "secret-name", "cm-adapter-serving-certs", "The secretname where the certificates should be written")
	flag.StringVar(&clusterDomain, "cluster-domain", "cluster.local", "Kubernetes cluster domain")
	flag.StringVar(&hostname, "hostname", "", "hostname as defined by pod.spec.hostname")
	flag.StringVar(&namespace, "namespace", "default", "namespace as defined by pod.metadata.namespace")
	flag.StringVar(&serviceName, "service-name", "", "service names that resolve to this Pod; comma separated")
	flag.Parse()

	// Initialize k8 goclient
	cfg, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(cfg)

	deployAPIRegistration(cfg)

	// Lets load up the secret and see if we even need to refresh/obtain a new certificate
	secret, err := clientset.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err == nil && secret != nil {
		privateKey := secret.Data["server.key"]
		publicKey := secret.Data["server.crt"]

		if verifyCertPair(publicKey, privateKey) {
			log.Println("Certificate is still valid. No need to refresh")
			os.Exit(0)
		}

	} else {
		log.Println("Error Obtaining secret %s: %s", secretName, err)
	}

	certificateSigningRequestName := fmt.Sprintf("%s-%s", serviceName, namespace)

	// Generate a private key, pem encode it, and save it to the filesystem.
	// The private key will be used to create a certificate signing request (csr)
	// that will be submitted to a Kubernetes CA to obtain a TLS certificate.
	log.Println("Generating Private Key")
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("unable to genarate the private key: %s", err)
	}

	pemKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Gather a list of DNS names that resolve to the services indicated
	dnsNames := serviceDomainName(serviceName, namespace, clusterDomain)

	// Generate the certificate request, pem encode it, and save it to the filesystem.
	certificateRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: dnsNames[0],
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           dnsNames,
	}

	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
	if err != nil {
		log.Fatalf("unable to generate the certificate request: %s", err)
	}

	csr, err := clientset.CertificatesV1beta1().CertificateSigningRequests().Get(certificateSigningRequestName, metav1.GetOptions{})
	if csr != nil && err == nil {
		log.Fatalf("error retrieving certificate signing request: %s", err)
	}
	log.Println("Delete old CSR")
	deletePolicy := metav1.DeletePropagationForeground

	clientset.CertificatesV1beta1().CertificateSigningRequests().Delete(certificateSigningRequestName, &metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	})
	log.Println("Deleted")
	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateRequest})
	log.Println("Create CSR")
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Create(&cert.CertificateSigningRequest{

		ObjectMeta: metav1.ObjectMeta{
			Name:      certificateSigningRequestName,
			Namespace: namespace,
		},
		Spec: cert.CertificateSigningRequestSpec{
			Groups:  []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:" + namespace},
			Request: certificateRequestBytes,
			Usages: []cert.KeyUsage{
				cert.UsageDigitalSignature,
				cert.UsageKeyEncipherment,
				cert.UsageServerAuth,
				cert.UsageClientAuth},
		},
	})
	if err != nil {
		log.Fatalf("unable to create the certificate signing request: %s", err)
	}
	log.Println("Approve CSR")

	condition := cert.CertificateSigningRequestCondition{
		Type:    cert.CertificateApproved,
		Reason:  "AutoApproved",
		Message: "Auto approving of all kubelet CSRs is enabled on bootkube",
	}
	csr.Status.Conditions = append(csr.Status.Conditions, condition)
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr)
	if err != nil {
		log.Fatalf("unable to approve certificate signing request: %s", err)
	}

	// We need to pause in order to let the controller sign the cert and update the CSR status
	time.Sleep(5 * time.Second)

	// Refresh status with cert now in it
	csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Get(certificateSigningRequestName, metav1.GetOptions{})
	if err != nil {
		log.Fatalf("error retrieving certificate signing request: %s", err)
	}
	log.Println("size returned %v", len(csr.Status.Certificate))

	block, _ := pem.Decode(csr.Status.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if !verifyCertPair(cert.Raw, pemKeyBytes) {
		log.Fatalf("Certificate pair provisioned is invalid!")
		os.Exit(1)
	}

	secretSpec := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{"server.key": pemKeyBytes, "server.crt": csr.Status.Certificate},
		Type: v1.SecretTypeOpaque,
	}
	secret, err = clientset.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err == nil && secret != nil {
		secret, err = clientset.CoreV1().Secrets(namespace).Update(&secretSpec)
		if err != nil {
			log.Println("unable to update secret with certificate: %s", err)
		}
	} else {
		secret, err = clientset.CoreV1().Secrets(namespace).Create(&secretSpec)
		if err != nil {
			log.Println("unable to create secret with certificate: %s", err)
		}
	}

	log.Printf("secret %s created", secret.GetName())

	os.Exit(0)
}

func serviceDomainName(name, namespace, domain string) []string {
	var retObj []string
	retObj = append(retObj, fmt.Sprintf("%s.%s.svc.%s", name, namespace, domain))
	retObj = append(retObj, fmt.Sprintf("%s.%s.svc", name, namespace))
	return retObj
}

func deployAPIRegistration(cfg *rest.Config) {

	log.Println("Checking For Kube Registration")
	extendset, err := extended.NewForConfig(cfg)
	reg, err := extendset.ApiregistrationV1beta1().APIServices().Get("v1beta1.custom.metrics.k8s.io", metav1.GetOptions{})
	if reg == nil && err == nil {
		log.Println("Creating Kube API Registration")
		reg, err = extendset.ApiregistrationV1beta1().APIServices().Create(&api.APIService{

			ObjectMeta: metav1.ObjectMeta{
				Name: "v1beta1.custom.metrics.k8s.io",
			},
			Spec: api.APIServiceSpec{
				Service: &api.ServiceReference{
					Name:      serviceName,
					Namespace: namespace,
				},
				Group:                 "custom.metrics.k8s.io",
				Version:               "v1beta1",
				InsecureSkipTLSVerify: false,
				CABundle:              []byte(os.Getenv("CA_FILE")),
				GroupPriorityMinimum:  100,
				VersionPriority:       100,
			},
		})
		if err != nil {
			log.Println("Error creating registration %s", err)
		}
	} else if err != nil {
		log.Println("Error while checking for registration %s", err)
	} else {
		log.Println("API Already exists")
	}

}

// Verify if a keypair is valid for TLS
func verifyCertPair(publicKey, privateKey []byte) bool {

	// First we verify that the public and private key pairs match and are valid
	parsedCert, err := tls.X509KeyPair(publicKey, privateKey)
	if err != nil {
		println("Error with the current cert: %s", err)
	} else {

		if parsedCert.Leaf != nil {
			println("Parsing not succesful. parsedCert.Leaf!=nil")
		} else {
			block, _ := pem.Decode(publicKey)

			// We attempt to parse the public key
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Println("failed to parse certificate: " + err.Error())
			}
			roots := x509.NewCertPool()

			// Loading the Kubeapi CA. This is mounted in this location in every pod
			content, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
			if err != nil {
				log.Println("Cant open CA file %s", err)
			}

			roots.AppendCertsFromPEM(content)

			// Now we verify that the public key is valid/signed by the kubeapi CA
			opts := x509.VerifyOptions{
				DNSName: serviceDomainName(serviceName, namespace, clusterDomain)[0],
				Roots:   roots,
			}
			if _, err := cert.Verify(opts); err != nil {
				log.Println("failed to verify certificate: " + err.Error())
			} else {
				log.Println("Certificate is still valid. No need to refresh")
				return true
			}

		}
	}
	return false
}
