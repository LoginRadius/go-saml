package internal

import (
	"crypto/rsa"
	"encoding/xml"
	"fmt"
	"github.com/LoginRadius/go-saml/util"
	"time"
)

type LogoutRequest struct {
	XMLName      xml.Name
	XMLNS        string       `xml:"xmlns:samlp,attr"`
	ID           string       `xml:"ID,attr"`
	Version      string       `xml:"Version,attr"`
	IssueInstant string       `xml:"IssueInstant,attr"`
	NotOnOrAfter string       `xml:"NotOnOrAfter,attr"`
	Destination  string       `xml:"Destination,attr"`
	Issuer       Issuer       `xml:"Issuer"`
	Signature    *Signature   `xml:"Signature,omitempty"`
	NameID       NameID       `xml:"NameID"`
	SessionIndex SessionIndex `xml:"SessionIndex"`
}

func NewLogoutRequest() *LogoutRequest {
	responseId := util.ID()
	issueInstant := time.Now().UTC().Format(time.RFC3339)
	notOnOrAfter := time.Now().Add(time.Minute * 10).UTC().Format(time.RFC3339)
	request := &LogoutRequest{
		XMLName: xml.Name{
			Local: "samlp:LogoutRequest",
		},
		XMLNS:        "urn:oasis:names:tc:SAML:2.0:protocol",
		ID:           responseId,
		Version:      "2.0",
		IssueInstant: issueInstant,
		NotOnOrAfter: notOnOrAfter,
		Destination:  "",
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
			Url:  "",
		},
		Signature: &Signature{
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
					Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				},
				SamlsigReference: SamlsigReference{
					XMLName: xml.Name{
						Local: "ds:Reference",
					},
					URI: "#" + responseId,
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
						Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
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
		NameID: NameID{
			XMLName: xml.Name{
				Local: "saml:NameID",
			},
			XMLNS:  "urn:oasis:names:tc:SAML:2.0:assertion",
			Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		},
		SessionIndex: SessionIndex{
			XMLName: xml.Name{
				Local: "samlp:SessionIndex",
			},
		},
	}
	return request
}

func (r *LogoutRequest) String() (string, error) {
	x, err := xml.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", err
	}
	return string(x), nil
}

func (r *LogoutRequest) SignedXml(idpPrivateKey *rsa.PrivateKey) (string, error) {
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

func (r *LogoutRequest) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("request not contain the id")
	}
	/*if r.IssueInstant.Add(MaxIssueDelay).Before(time.Now()) {
		return fmt.Errorf("request expired at %s", r.IssueInstant.Add(MaxIssueDelay))
	}*/
	if r.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2.0 got %v", r.Version)
	}
	return nil
}
