package internal

import (
	"encoding/xml"
)

func GetIdpEntityDescriptor() *IDPEntityDescriptor {
	return &IDPEntityDescriptor{
		XMLName: xml.Name{
			Local: "EntityDescriptor",
		},
		DS:        "http://www.w3.org/2000/09/xmldsig#",
		XMLNS:     "urn:oasis:names:tc:SAML:2.0:metadata",
		ASSERTION: "urn:oasis:names:tc:SAML:2.0:assertion",
		IDPSSODescriptor: IDPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			WantAuthnRequestsSigned:    "false",
			SigningKeyDescriptor: KeyDescriptor{
				XMLName: xml.Name{
					Local: "KeyDescriptor",
				},

				Use: "signing",
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
		},
	}
}
