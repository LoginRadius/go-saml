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

// Supported signature algorithms for responses
const (
	SignatureAlgorithmRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureAlgorithmRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#sha256"
)

// Supported digest algorithms for responses
const (
	DigestAlgorithmSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestAlgorithmSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
)

type IdentityProvider struct {
	IsIdpInitiated       bool
	Issuer               string
	Audiences            []string
	IDPCert              string
	IDPKey               string
	SPCert               string
	IDPCertFilePath      string
	IDPKeyFilePath       string
	SPCertFilePath       string
	Attributes           []map[string]string
	SignatureAlgorithm   string // RSA-SHA256 is the default
	SignaturePrefix      string
	DigestAlgorithm      string // SHA256 is the default
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
