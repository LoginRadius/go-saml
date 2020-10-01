package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	lib "github.com/LoginRadius/go-saml/internal"
	"github.com/LoginRadius/go-saml/templates"
	"github.com/LoginRadius/go-saml/util"
)

var samlPostFormTemplate = templates.SAMLResponsePostForm()

func (idp *IdentityProvider) NewSignedLoginResponse() (string, error) {
	err := idp.validate()
	if err != nil {
		return "", err
	}
	response := lib.NewResponse()
	response.SetIdpCertificate(idp.x509IdpCertificate)
	resposne.SetSignatureAlgorithm(idp.signatureAlgorithm())
	resposne.SetDigestAlgorithm(idp.digestAlgorithm())
	response.SetIssuer(idp.Issuer)
	response.SetDestination(idp.ACSLocation)
	response.SetNameId(idp.NameIdentifierFormat, idp.NameIdentifier)
	response.SetSessionIndex(idp.SessionIndex)
	response.AddAudience(idp.Audiences)
	response.AddAttributes(idp.Attributes)
	if idp.samlRequestParam != nil {
		response.SetInResponseTo(idp.samlRequestParam.AuthnRequest.ID)
	}
	signedXml, err := response.SignedXml(idp.idpPrivateKey)
	if err != nil {
		return "", err
	}
	return signedXml, nil
}

func (idp *IdentityProvider) NewSignedLogoutResponse() (string, error) {
	//err := idp.validate()
	response := lib.NewLogoutResponse()
	response.Issuer.Url = idp.Issuer
	response.Destination = idp.LogoutUrl
	err := idp.parseIdpX509Certificate()
	if err != nil {
		return "", err
	}
	err = idp.parsePrivateKey()
	if err != nil {
		return "", err
	}
	response.Signature.KeyInfo.X509Data.X509Certificate.Cert = idp.x509IdpCertificate
	if idp.samlRequestParam != nil {
		response.InResponseTo = idp.samlRequestParam.LogoutRequest.ID
	}
	resposne.SetSignatureAlgorithm(idp.signatureAlgorithm())
	resposne.SetDigestAlgorithm(idp.digestAlgorithm())
	signedXml, err := response.SignedXml(idp.idpPrivateKey)
	if err != nil {
		return "", err
	}
	return signedXml, nil
}

func (idp *IdentityProvider) MetaDataResponse() (string, error) {
	metadata := lib.GetIdpEntityDescriptor()
	metadata.EntityId = idp.Issuer
	metadata.IDPSSODescriptor.SigningKeyDescriptor.KeyInfo.X509Data.X509Certificate.Cert = util.GetRawCertificate(idp.IDPCert)
	if len(idp.SingleSignOnService) > 0 {
		for i := 0; i < len(idp.SingleSignOnService); i++ {
			metadata.IDPSSODescriptor.SingleSignOnService = append(metadata.IDPSSODescriptor.SingleSignOnService, lib.SingleSignOnService{
				XMLName: xml.Name{
					Local: "SingleSignOnService",
				},
				Index:    fmt.Sprintf(`%d`, i),
				Binding:  idp.SingleSignOnService[i].Binding,
				Location: idp.SingleSignOnService[i].Location,
			})
		}
	}
	if len(idp.SingleSignOutService) > 0 {
		for i := 0; i < len(idp.SingleSignOutService); i++ {
			metadata.IDPSSODescriptor.SingleLogoutService = append(metadata.IDPSSODescriptor.SingleLogoutService, lib.SingleLogoutService{
				XMLName: xml.Name{
					Local: "SingleLogoutService",
				},
				Index:    fmt.Sprintf(`%d`, i),
				Binding:  idp.SingleSignOutService[i].Binding,
				Location: idp.SingleSignOutService[i].Location,
			})
		}
	}
	b, err := xml.MarshalIndent(metadata, "", "    ")
	if err != nil {
		return "", err
	}
	newMetadata := fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?>\n%s", b)
	return string(newMetadata), nil
}

func (idp *IdentityProvider) ValidateAuthnRequest(method string, query url.Values, payload url.Values) *Reject {
	samlRequestParam, err := prepareSamlRequestParam(method, query, payload, "AuthnRequest")
	if err != nil {
		return &Reject{err, "SAML_REQUEST_NOT_VALID"}
	}
	if err = samlRequestParam.CheckSignature(idp); err != nil {
		return &Reject{err, "SAML_SINGING_CERTIFICATE_MISMATCH"}
	}
	if err = samlRequestParam.AuthnRequest.Validate(); err != nil {
		return &Reject{err, "SAML_REQUEST_NOT_VALID"}
	}
	idp.RelayState = samlRequestParam.RelayState
	idp.samlRequestParam = samlRequestParam
	return nil
}

func (idp *IdentityProvider) ValidateLogoutRequest(method string, query url.Values, payload url.Values) *Reject {
	samlRequestParam, err := prepareSamlRequestParam(method, query, payload, "LogoutRequest")
	if err != nil {
		return &Reject{err, "SAML_REQUEST_NOT_VALID"}
	}
	if err = samlRequestParam.CheckSignature(idp); err != nil {
		return &Reject{err, "SAML_SINGING_CERTIFICATE_MISMATCH"}
	}
	if err = samlRequestParam.LogoutRequest.Validate(); err != nil {
		return &Reject{err, "SAML_REQUEST_NOT_VALID"}
	}
	idp.RelayState = samlRequestParam.RelayState
	idp.samlRequestParam = samlRequestParam
	return nil
}

func (idp *IdentityProvider) AddAttribute(name string, value string, format string) {
	idp.Attributes = append(idp.Attributes, map[string]string{
		"Name":   name,
		"Value":  value,
		"Format": format,
	})
}

func (idp *IdentityProvider) AddSingleSignOnService(service MetadataBinding) {
	idp.SingleSignOnService = append(idp.SingleSignOnService, service)
}

func (idp *IdentityProvider) AddSingleSignOutService(service MetadataBinding) {
	idp.SingleSignOutService = append(idp.SingleSignOutService, service)
}

func (idp *IdentityProvider) AuthnRequestTTL(duration time.Duration) {
	lib.MaxIssueDelay = duration
}

func (idp *IdentityProvider) ResponseHtml(signedXML string, requestType string) (string, error) {
	var b bytes.Buffer
	location := idp.ACSLocation
	if requestType == "LogoutResponse" {
		location = idp.LogoutUrl
	}
	data := struct {
		URL          string
		SAMLResponse string
		RelayState   string
	}{
		URL:          location,
		SAMLResponse: base64.StdEncoding.EncodeToString([]byte(signedXML)),
		RelayState:   idp.RelayState,
	}
	if err := samlPostFormTemplate.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (idp *IdentityProvider) validateIDPX509Certificate() error {
	if idp.IDPCert == "" {
		return errors.New("SAML Configuration: IDP Certificate is empty")
	}
	err := util.ValidateCertificatePem(idp.IDPCert)
	if err != nil {
		return err
	}
	return nil
}

func (idp *IdentityProvider) validateSPX509Certificate() error {
	if idp.SPCert == "" {
		return errors.New("SAML Configuration: SP Certificate is empty")
	}
	err := util.ValidateCertificatePem(idp.SPCert)
	if err != nil {
		return err
	}
	return nil
}

func (idp *IdentityProvider) rawIdpX509Certificate() error {
	err := idp.validateIDPX509Certificate()
	if err != nil {
		return err
	}
	idp.x509IdpCertificate = util.GetRawCertificate(idp.IDPCert)
	return nil
}

func (idp *IdentityProvider) rawSPX509Certificate() error {
	err := idp.validateSPX509Certificate()
	if err != nil {
		return err
	}
	idp.x509SpCertificate = util.GetRawCertificate(idp.SPCert)
	return nil
}

func (idp *IdentityProvider) parseIdpX509Certificate() error {
	err := idp.validateIDPX509Certificate()
	if err != nil {
		return err
	}
	idp.x509IdpCertificate = util.GetRawCertificate(idp.IDPCert)
	return nil
}

func (idp *IdentityProvider) parseSpX509Certificate() error {
	err := idp.validateSPX509Certificate()
	if err != nil {
		return err
	}
	idp.x509SpCertificate = util.GetRawCertificate(idp.SPCert)
	return nil
}

func (idp *IdentityProvider) parsePrivateKey() error {
	if idp.IDPKey == "" {
		return errors.New("SAML Configuration: IDP Private Key is empty")
	}
	privateKey, err := util.ParseRsaPrivateKeyPem(idp.IDPKey)
	if err != nil {
		return err
	}
	idp.idpPrivateKey = privateKey
	return nil
}

func (idp *IdentityProvider) validate() error {
	err := idp.parseIdpX509Certificate()
	if err != nil {
		return err
	}
	err = idp.parsePrivateKey()
	if err != nil {
		return err
	}
	if !idp.IsIdpInitiated {
		err := idp.parseSpX509Certificate()
		if err != nil {
			return err
		}
	}
	if idp.Issuer == "" {
		return errors.New("SAML Configuration: Issuer is empty")
	}
	if idp.ACSLocation == "" {
		return errors.New("SAML Configuration: ACSLocation is empty")
	}

	if idp.ACSBinging == "" {
		return errors.New("SAML Configuration: ACSBinging is empty")
	}

	if idp.ACSBinging != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
		return errors.New("SAML Configuration: ACSBinging is invalid")
	}

	if idp.NameIdentifierFormat == "" {
		return errors.New("SAML Configuration: NameID Format is empty")
	}
	if idp.NameIdentifier == "" {
		return errors.New("SAML Configuration: NameID value is empty")
	}
	if idp.SessionIndex == "" {
		return errors.New("SAML Configuration: SessionIndex is empty")
	}
	if len(idp.Audiences) == 0 {
		return errors.New("SAML Configuration: Audience is empty")
	}
	if len(idp.Attributes) > 0 {
		for _, attr := range idp.Attributes {
			attrName, attrNameOk := attr["Name"]
			attrFormat, attrFormatOk := attr["Format"]
			_, attrValueOk := attr["Value"]
			if !(attrNameOk && attrName != "") {
				return errors.New("SAML Configuration: Attributes Name is not defined or empty")
			}
			if !(attrFormatOk && attrFormat != "") {
				return errors.New("SAML Configuration: Attributes Format is not defined or empty")
			}
			if !(attrValueOk) {
				return errors.New("SAML Configuration: Attributes Value is not defined")
			}
		}
	}
	return nil
}

func (idp *IdentityProvider) signatureAlgorithm() string {
	if idp.SignatureAlgorithm == "" {
		return SignatureAlgorithmRSASHA256
	}

	return idp.SignatureAlgorithm
}

func (idp *IdentityProvider) digestAlgorithm() string {
	if idp.DigestAlgorithm == "" {
		return DigestAlgorithmSHA256
	}

	return idp.DigestAlgorithm
}

func prepareSamlRequestParam(method string, query url.Values, payload url.Values, requestType string) (*SamlRequestParam, error) {
	samlRequestParam := &SamlRequestParam{Method: method}
	switch method {
	case "GET":
		samlRequest := query.Get("SAMLRequest")
		sigAlg := query.Get("SigAlg")
		signature := query.Get("Signature")
		if samlRequest == "" {
			return nil, errors.New("AuthnRequest: SamlRequest is not found")
		}
		/*if sigAlg==""{
			return nil, errors.New("AuthnRequest: Signature Algo is not found")
		}*/
		/*if signature==""{
			return nil, errors.New("AuthnRequest: signature is not found")
		}*/
		samlRequestParam.Signature = signature
		samlRequestParam.RelayState = query.Get("RelayState")
		samlRequestParam.SAMLRequest = samlRequest
		samlRequestParam.SigAlg = sigAlg
		compressedRequest, err := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
		if err != nil {
			return nil, fmt.Errorf("cannot decode request: %s", err)
		}
		samlRequestParam.RequestBuffer, err = ioutil.ReadAll(flate.NewReader(bytes.NewReader(compressedRequest)))
		if err != nil {
			return nil, fmt.Errorf("cannot decompress request: %s", err)
		}
	case "POST":
		var err error
		samlRequest := payload.Get("SAMLRequest")
		samlRequestParam.RelayState = payload.Get("RelayState")
		if samlRequest == "" {
			return nil, errors.New("AuthnRequest: SamlRequest is not found")
		}
		samlRequestParam.RequestBuffer, err = base64.StdEncoding.DecodeString(payload.Get("SAMLRequest"))
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("method not allowed")
	}

	if requestType == "AuthnRequest" {
		if err := samlRequestParam.ParseAuthnRequest(); err != nil {
			return nil, err
		}
	} else {
		if err := samlRequestParam.ParseLogoutRequest(); err != nil {
			return nil, err
		}
	}
	return samlRequestParam, nil
}
