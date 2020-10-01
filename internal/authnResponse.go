package internal

import (
	"encoding/xml"
	"github.com/LoginRadius/go-saml/util"
	"time"
)

func NewResponse() *Response {
	responseId := util.ID()
	assertionId := util.ID()
	issueInstant := time.Now().UTC().Format(time.RFC3339)
	return &Response{
		XMLName: xml.Name{
			Local: "samlp:Response",
		},
		SAMLP:        "urn:oasis:names:tc:SAML:2.0:protocol",
		SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
		ID:           responseId,
		Version:      "2.0",
		IssueInstant: issueInstant,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
		},
		Status: Status{
			XMLName: xml.Name{
				Local: "samlp:Status",
			},
			StatusCode: StatusCode{
				XMLName: xml.Name{
					Local: "samlp:StatusCode",
				},
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: Assertion{
			XMLName: xml.Name{
				Local: "saml:Assertion",
			},
			XSI:          "http://www.w3.org/2001/XMLSchema-instance",
			XS:           "http://www.w3.org/2001/XMLSchema",
			SAML:         "urn:oasis:names:tc:SAML:2.0:assertion",
			Version:      "2.0",
			ID:           assertionId,
			IssueInstant: issueInstant,
			Issuer: Issuer{
				XMLName: xml.Name{
					Local: "saml:Issuer",
				},
			},
			Signature: Signature{
				XMLName: xml.Name{
					Local: "ds:Signature",
				},
				SAMLSIG: "http://www.w3.org/2000/09/xmldsig#",
				SignedInfo: SignedInfo{
					XMLName: xml.Name{
						Local: "ds:SignedInfo",
					},
					CanonicalizationMethod: CanonicalizationMethod{
						XMLName: xml.Name{
							Local: "ds:CanonicalizationMethod",
						},
						Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
					},
					SignatureMethod: SignatureMethod{
						XMLName: xml.Name{
							Local: "ds:SignatureMethod",
						},

						Algorithm: "", // populated by SetSignatureAlgorithm
					},
					SamlsigReference: SamlsigReference{
						XMLName: xml.Name{
							Local: "ds:Reference",
						},
						URI: "#" + assertionId,
						Transforms: Transforms{
							XMLName: xml.Name{
								Local: "ds:Transforms",
							},
							Transform: []Transform{Transform{
								XMLName: xml.Name{
									Local: "ds:Transform",
								},
								Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
							}, Transform{
								XMLName: xml.Name{
									Local: "ds:Transform",
								},
								Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
							}},
						},
						DigestMethod: DigestMethod{
							XMLName: xml.Name{
								Local: "ds:DigestMethod",
							},
							Algorithm: "", // populated by SetDigestAlgorithm
						},
						DigestValue: DigestValue{
							XMLName: xml.Name{
								Local: "ds:DigestValue",
							},
						},
					},
				},
				SignatureValue: SignatureValue{
					XMLName: xml.Name{
						Local: "ds:SignatureValue",
					},
				},
				KeyInfo: KeyInfo{
					XMLName: xml.Name{
						Local: "ds:KeyInfo",
					},
					X509Data: X509Data{
						XMLName: xml.Name{
							Local: "ds:X509Data",
						},
						X509Certificate: X509Certificate{
							XMLName: xml.Name{
								Local: "ds:X509Certificate",
							},
						},
					},
				},
			},
			Subject: Subject{
				XMLName: xml.Name{
					Local: "saml:Subject",
				},
				NameID: NameID{
					XMLName: xml.Name{
						Local: "saml:NameID",
					},
					Format: "",
				},
				SubjectConfirmation: SubjectConfirmation{
					XMLName: xml.Name{
						Local: "saml:SubjectConfirmation",
					},
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: SubjectConfirmationData{
						XMLName: xml.Name{
							Local: "saml:SubjectConfirmationData",
						},
						NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339),
					},
				},
			},
			Conditions: Conditions{
				XMLName: xml.Name{
					Local: "saml:Conditions",
				},
				NotBefore:    time.Now().Add(time.Minute * -5).UTC().Format(time.RFC3339),
				NotOnOrAfter: time.Now().Add(time.Minute * 5).UTC().Format(time.RFC3339),
				AudienceRestriction: AudienceRestriction{
					XMLName: xml.Name{
						Local: "saml:AudienceRestriction",
					},
					Audiences: []Audience{},
				},
			},
			AuthnStatement: AuthnStatement{
				XMLName: xml.Name{
					Local: "saml:AuthnStatement",
				},
				AuthnInstant: issueInstant,
				SessionIndex: "",
				AuthnContext: AuthnContext{
					XMLName: xml.Name{
						Local: "saml:AuthnContext",
					},
					AuthnContextClassRef: AuthnContextClassRef{
						XMLName: xml.Name{
							Local: "saml:AuthnContextClassRef",
						},
						Transport: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
					},
				},
			},
			AttributeStatement: AttributeStatement{
				XMLName: xml.Name{
					Local: "saml:AttributeStatement",
				},
				Attributes: []Attribute{},
			},
		},
	}
}

func (r *Response) String() (string, error) {
	x, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}
	return string(x), nil
}

func (r *Response) AddAttributes(attributes []map[string]string) {
	if len(attributes) > 0 {
		for _, attr := range attributes {
			r.Assertion.AttributeStatement.Attributes = append(r.Assertion.AttributeStatement.Attributes, Attribute{
				XMLName: xml.Name{
					Local: "saml:Attribute",
				},
				Name:       attr["Name"],
				NameFormat: attr["Format"],
				AttributeValues: AttributeValue{
					XMLName: xml.Name{
						Local: "saml:AttributeValue",
					},
					XS:    "http://www.w3.org/2001/XMLSchema",
					XSI:   "http://www.w3.org/2001/XMLSchema-instance",
					Type:  "xs:string",
					Value: attr["Value"],
				},
			})
		}
	}
}

func (r *Response) AddAudience(audiences []string) {
	for _, audience := range audiences {
		r.Assertion.Conditions.AudienceRestriction.Audiences = append(r.Assertion.Conditions.AudienceRestriction.Audiences, Audience{
			XMLName: xml.Name{
				Local: "saml:Audience",
			},
			Value: audience,
		})
	}
}

func (r *Response) SetIdpCertificate(certPem string) {
	r.Assertion.Signature.KeyInfo.X509Data.X509Certificate.Cert = certPem
}

func (r *Response) SetIssuer(issuer string) {
	r.Issuer.Url = issuer
	r.Assertion.Issuer.Url = issuer
}

func (r *Response) SetDestination(destination string) {
	r.Destination = destination
	r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = destination
}

func (r *Response) SetNameId(format string, value string) {
	r.Assertion.Subject.NameID.Format = format
	r.Assertion.Subject.NameID.Value = value
}

func (r *Response) SetSessionIndex(sessionIndex string) {
	r.Assertion.AuthnStatement.SessionIndex = sessionIndex
}

func (r *Response) SetInResponseTo(inResponseTo string) {
	r.InResponseTo = inResponseTo
	r.Assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo = inResponseTo
}

func (r *Response) SetSignatureAlgorithm(alg string) {
	r.Assertion.Signature.SignedInfo.SignatureMethod.Algorithm = alg
}

func (r *Response) SetDigestAlgorithm(alg string) {
	r.Assertion.Signature.SignedInfo.SamlsigReference.DigestMethod.Algorithm = alg
}

func (r *Response) SignedXml(idpPrivateKey interface{}) (string, error) {
	xmlStr, err := r.String()
	if err != nil {
		return "", err
	}
	signedXml, err := util.Sign(xmlStr, idpPrivateKey)
	if err != nil {
		return "", err
	}
	return signedXml, nil
}
