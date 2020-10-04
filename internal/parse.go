package internal

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/LoginRadius/go-saml"
	"github.com/LoginRadius/go-saml/util"
	"github.com/ma314smith/signedxml"
	"net/url"
	"strings"
)

var signAlgorithm = map[string]x509.SignatureAlgorithm{
	"http://www.w3.org/2001/04/xmldsig-more#rsa-md2":      x509.MD2WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-md5":      x509.MD5WithRSA,
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          x509.SHA1WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   x509.SHA256WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   x509.SHA384WithRSA,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   x509.SHA512WithRSA,
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":          x509.DSAWithSHA1,
	"http://www.w3.org/2000/09/xmldsig#dsa-sha256":        x509.DSAWithSHA256,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":   x509.ECDSAWithSHA1,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": x509.ECDSAWithSHA256,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": x509.ECDSAWithSHA384,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": x509.ECDSAWithSHA512,
}

type SamlRequestParam struct {
	Method        string
	RequestBuffer []byte
	SAMLRequest   string
	RelayState    string
	SigAlg        string
	Signature     string
	AuthnRequest  *AuthnRequest
	LogoutRequest *LogoutRequest
}

func (s *SamlRequestParam) GetOctetString() string {
	if s.Method == "GET" {
		var strArr []string
		strArr = append(strArr, fmt.Sprintf(`SAMLRequest=%s`, url.QueryEscape(s.SAMLRequest)))
		if s.RelayState != "" {
			strArr = append(strArr, fmt.Sprintf(`RelayState=%s`, url.QueryEscape(s.RelayState)))
		}
		strArr = append(strArr, fmt.Sprintf(`SigAlg=%s`, url.QueryEscape(s.SigAlg)))
		return strings.Join(strArr, "&")
	}
	return ""
}

func (s *SamlRequestParam) ParseAuthnRequest() error {
	var authnRequest AuthnRequest
	if err := xml.Unmarshal(s.RequestBuffer, &authnRequest); err != nil {
		return err
	}
	s.AuthnRequest = &authnRequest
	return nil
}

func (s *SamlRequestParam) ParseLogoutRequest() error {
	var logoutRequest LogoutRequest
	if err := xml.Unmarshal(s.RequestBuffer, &logoutRequest); err != nil {
		return err
	}
	s.LogoutRequest = &logoutRequest
	return nil
}

func (s *SamlRequestParam) CheckSignature(idp *saml.IdentityProvider) error {
	if s.Method == "GET" {
		if s.SigAlg != "" && s.Signature != "" {
			sigvalue, err := base64.StdEncoding.DecodeString(s.Signature)
			if err != nil {
				return err
			}
			certificate, err := util.ParseCertificatePem(idp.SPCert)
			if err != nil {
				return err
			}
			signedInfo := s.GetOctetString()
			return certificate.CheckSignature(signAlgorithm[s.SigAlg], []byte(signedInfo), []byte(sigvalue))
		}
		return nil

	} else if (s.AuthnRequest != nil && s.AuthnRequest.Signature != nil) || (s.LogoutRequest != nil && s.LogoutRequest.Signature != nil) {
		validator, err := signedxml.NewValidator(string(s.RequestBuffer))
		if err != nil {
			return err
		}
		_, err = validator.ValidateReferences()
		if err != nil {
			return err
		}
	}
	return nil
}
