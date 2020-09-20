# go-saml
High-level API library for Single Sign On with SAML 2.0 based on  [etree](https://github.com/beevik/etree) and [signedxml](https://github.com/ma314smith/signedxml), a pure Go implementation.
The library provides the Identity Provider Implementation with support of both IDPInitiated and SPInitiated flow.

## Features
* Generating identity provider metadata
* Validating Redirect/Post Binding signed/unsigned AuthnRequests
* Generating Post signed Responses
* Validating Redirect/Post Binding signed/unsigned LogoutRequest
* Generating Post signed LogoutResponses
* SessionIndex

## Installation
Install `go-saml` into your `$GOPATH` using go get:
```
go get github.com/LoginRadius/go-saml
```
## Usage
Below are samples to show how you might use the library.

### Create Idp Provider Instance
```
idp := saml.IdentityProvider{
    IsIdpInitiated:       false,
    Issuer:               "https://identity-provider.com/",
    Audiences:            "https://service-provider.com/",
    IDPCert:              "<IDPCert PEM Format>",
    IDPKey:               "<IDPKey PEM Format>",
    SPCert:               "<SPCert PEM Format>",
    NameIdentifier:       "john@idp.com",
    NameIdentifierFormat: saml.AttributeFormatUnspecified,
    ACSLocation:          "https://service-provider-acs.com", //Service Provider Login Url
    ACSBinging:           saml.HTTPPostBinding,
    SessionIndex:         "1ac5bc03-06a1-413d-8542-e7a7e7d9e9f2",
    LogoutUrl:            "https://service-provider-acs.com/logout" //Service Provider Logout Url
}

//Add Attributes
idp.AddAttribute("Fname", "john", saml.AttributeFormatUnspecified)
```

### Validate and Parse AuthnRequest
```
//This validate the AuthnRequest and set parsed value in the idp instance, 
//that used in Generating the SAML Response with InResponseTo property.

//Get Querystring and Payload values from request with url.Value{} type
validationError := idp.ValidateAuthnRequest(method"POST",query url.Values,payload url.Values);
if validationError !=nil {
  return validationError
}
```

### Generate Login Response
```
signedXML, signedXMLErr := idp.NewSignedLoginResponse()
if signedXMLErr != nil {
    return signedXMLErr
}

//Generate html content for Post
html, err := idp.ResponseHtml(signedXML, "Response")
if err !=nil {
  return err
}
```
### Validate and Parse Logout Request
```
//This validate the AuthnRequest and set parsed value in the idp instance, 
//that used in Generating the SAML Logout Response with InResponseTo property

//Get Querystring and Payload values from request with url.Value{} type
validationError := idp.ValidateLogoutRequest(method"POST",query url.Values,payload url.Values);
if validationError !=nil {
  return validationError
}
```

### Generate Logout Response
```
signedXML, signedXMLErr := idp.NewSignedLoginResponse()
if signedXMLErr != nil {
    return signedXMLErr
}

//Generate html content for Post
html, err := idp.ResponseHtml(signedXML, "LogoutResponse")
if err !=nil {
  return err
}
```

### Metadata Identity Provider
```
idp := saml.IdentityProvider{
    Issuer:               "https://identity-provider.com/",
    Audiences:            "https://service-provider.com/",
    IDPCert:              "<IDPCert PEM Format>",
    NameIdentifierFormat: saml.AttributeFormatUnspecified,
}

idp.AddSingleSignOnService(saml.MetadataBinding{
    Binding:  saml.HTTPPostBinding,
    Location: "https://identity-provider.com/saml/post",
})

idp.AddSingleSignOnService(saml.MetadataBinding{
    Binding:  saml.HTTPRedirectBinding,
    Location: "https://identity-provider.com/saml/redirect",
})

idp.AddSingleSignOutService(saml.MetadataBinding{
    Binding:  saml.HTTPPostBinding,
    Location: "https://identity-provider.com/saml/post/logout",
})

// Generate xml for IDP Metadata
xml, xmlerr :=  idp.MetaDataResponse()

```
### Example
Please see [examples](examples) for how to use the library to be an identity provider.

## Contributing
Would love any contributions you, having including better documentation, tests, or more robust functionality. Please follow the [contributing guide](CONTRIBUTING.md)

## License
[MIT](LICENSE)