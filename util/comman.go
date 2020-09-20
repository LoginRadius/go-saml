package util

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/ma314smith/signedxml"
	uuid "github.com/satori/go.uuid"
	"regexp"
	"strings"
)

func ID() string {
	u := uuid.NewV4()
	return "_" + u.String()
}

func ValidateCertificatePem(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("failed to parse certificate PEM")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}

func GetRawCertificate(cert string) string {
	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	cert = re.ReplaceAllString(cert, "")
	cert = strings.Trim(cert, " \n")
	cert = strings.Replace(cert, "\r", "", -1)
	cert = strings.Replace(cert, "\n", "", -1)
	return cert
}

func ParseRsaPrivateKeyPem(privPEM string) (interface{}, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		privateKeyPkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		privateKey = privateKeyPkcs8.(*rsa.PrivateKey)
	}

	return privateKey, nil
}

func ParseCertificatePem(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func Sign(a string, k interface{}) (string, error) {
	signer, err := signedxml.NewSigner(a)
	if err != nil {
		return "", err
	}
	signedXML, err := signer.Sign(k)
	if err != nil {
		return "", err
	}
	return signedXML, nil
}
