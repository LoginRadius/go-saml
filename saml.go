package saml

const (
	NameIdFormatPersistent      = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIdFormatTransient       = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIdFormatEmailAddress    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIdFormatUnspecified     = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIdFormatX509SubjectName = "urn:oasis:names:tc:SAML:1.1:nameid-format:x509SubjectName"

	HTTPPostBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

	AttributeFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	AttributeFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	AttributeFormatUri         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
)

type IdentityProvider struct {
	IsIdpInitiated       bool
	Issuer               string
	Audiences            []string
	IDPCert              string
	IDPKey               string
	SPCert               string
	Attributes           []map[string]string
	SignatureAlgorithm   string
	SignaturePrefix      string
	DigestAlgorithm      string
	LifetimeInSeconds    int64
	NameIdentifier       string
	NameIdentifierFormat string
	ACSLocation          string
	ACSBinging           string
	LogoutUrl            string
	RelayState           string
	SessionIndex         string
	SingleSignOnService  []MetadataBinding
	SingleSignOutService []MetadataBinding
	idpPrivateKey        interface{}
	x509IdpCertificate   string
	x509SpCertificate    string
	samlRequestParam     *SamlRequestParam
}

type MetadataBinding struct {
	Binding  string
	Location string
}

type Reject struct {
	Error  error
	Reason string
}
