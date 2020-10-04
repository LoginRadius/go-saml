package examples

import (
	"fmt"
	"github.com/LoginRadius/go-saml"
	"github.com/LoginRadius/go-saml/examples/utitlity"
	"net/url"
	"time"
)

func LoginResponseExample() {
	idp := saml.IdentityProvider{
		IsIdpInitiated:       false,
		Issuer:               "https://identity-provider.com/",
		Audiences:            []string{"https://service-provider.com/"},
		IDPCert:              utitlity.GetIdpCertificate(),
		IDPKey:               utitlity.GetIdpPrivateKey(),
		SPCert:               utitlity.GetSpCertificate(),
		NameIdentifier:       "john@idp.com",
		NameIdentifierFormat: saml.NameIdFormatUnspecified,
		ACSLocation:          "https://service-provider.com/", //Service Provider Login Url
		ACSBinging:           saml.HTTPPostBinding,
		SessionIndex:         "1ac5bc03-06a1-413d-8542-e7a7e7d9e9f2",
	}

	idp.AddAttribute("UserUid", "23456789098765432234", saml.AttributeFormatUnspecified)
	idp.AddAttribute("Position", "manager", saml.AttributeFormatUnspecified)

	//Default AuthnRequest expire time is 10 min, use below to customize
	idp.AuthnRequestTTL(time.Hour * 888888)

	//This validate the AuthnRequest and set parse value in the idp instance,
	//When NewSignedLoginResponse called, InResponseTo property added from the parsed AuthnRequest
	_, validationError := idp.ValidateAuthnRequest("POST", url.Values{}, utitlity.GetSampleAuthnRequest())
	if validationError != nil {
		fmt.Println(validationError)
	}

	signedXML, signedXMLErr := idp.NewSignedLoginResponse()
	if signedXMLErr != nil {
		fmt.Println("signedXMLErr", signedXMLErr)
		return
	}

	fmt.Println("------------------signedXML------------------\n", signedXML)

	//Generate html content for Post
	html, err := idp.ResponseHtml(signedXML, "Response")
	if err != nil {
		fmt.Println("htmlErr", err)
		return
	}

	fmt.Println("------------------Post Form------------------\n", html)

}
