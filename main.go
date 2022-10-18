package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"log"
	"os"
	"time"
)

type CertificateType string

const (
	EndpointCertificate  CertificateType = "certificate"
	CertificateAuthority CertificateType = "ca"
)

type Certificate struct {
	Pem                string          `json:"pem"`
	CertType           CertificateType `json:"certType"`
	NotAfterTimeMillis int64           `json:"notAfterTimeMillis"`
	NotAfterTime       time.Time       `json:"notAfterTime"`
	NotBeforeInMillis  int64           `json:"notBeforeInMillis"`
	NotBeforeTime      time.Time       `json:"notBeforeTime"`
}

type Certificates struct {
	Domain     string        `json:"domain"`
	PrivateKey string        `json:"privateKey"`
	Certs      []Certificate `json:"certs"`
}

func main() {
	domain := os.Getenv("CERT_DOMAIN")

	if domain == "" {
		log.Fatalln(fmt.Errorf("CERT_DOMAIN environment must be present"))
	}
	secretName := fmt.Sprintf("cert.wildcard.%s", domain)
	userHome, err := os.UserHomeDir()
	if err != nil {
		log.Printf("%v", err)
		log.Printf("user home is not defined, defaulting to /root")
		userHome = "/root"
	}
	certsFolderName := fmt.Sprintf("%s/certs", userHome)
	certFileName := fmt.Sprintf("%s/certs/%s.crt", userHome, domain)
	keyFileName := fmt.Sprintf("%s/certs/%s.key", userHome, domain)
	//caFileName := fmt.Sprintf("%s/certs/%s.ca", userHome, domain)

	client, err := getRouteSecretsManagerClient()
	if err != nil {
		log.Fatalln(err)
	}
	getValInput := secretsmanager.GetSecretValueInput{SecretId: &secretName}
	getValOutput, err := client.GetSecretValue(context.Background(), &getValInput)
	if err != nil {
		log.Fatal(err)
	}
	certs := Certificates{}
	err = json.Unmarshal([]byte(*getValOutput.SecretString), &certs)
	if err != nil {
		log.Fatal(err)
	}

	//do we have a file already

	err = ensureFolderExists(certsFolderName)
	if err != nil {
		log.Fatal(err)
	}

	needsUpdate := false
	if _, err := os.Stat(keyFileName); err == nil {
		keyBytes, err := os.ReadFile(keyFileName)
		if err != nil {
			log.Fatal(err)
		}
		if certs.PrivateKey != string(keyBytes) {
			needsUpdate = true
		}

	} else if errors.Is(err, os.ErrNotExist) {
		needsUpdate = true

	} else {
		log.Fatal(err)

	}

	if needsUpdate {
		kf, err := os.OpenFile(keyFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			log.Fatal(err)
		}
		defer kf.Close()
		kf.Truncate(0)
		kf.WriteString(certs.PrivateKey + "\n")

		certF, err := os.OpenFile(certFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			log.Fatal(err)
		}
		defer certF.Close()
		certF.Truncate(0)
		for _, cert := range certs.Certs {
			if cert.CertType == EndpointCertificate {
				certF.WriteString(cert.Pem + "\n")
			}
		}
		for _, cert := range certs.Certs {
			if cert.CertType == CertificateAuthority {
				certF.WriteString(cert.Pem + "\n")
			}
		}

	}

}

func ensureFolderExists(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			return err
		} else {
			return nil
		}
	}
	return nil
}

func getRoute53Client() (*route53.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := route53.NewFromConfig(cfg)

	return client, nil
}
func getRouteSecretsManagerClient() (*secretsmanager.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}
	client := secretsmanager.NewFromConfig(cfg)

	return client, nil
}
