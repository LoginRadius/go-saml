package examples

import (
	"fmt"

	"github.com/LoginRadius/go-saml"
	"github.com/LoginRadius/go-saml/examples/utitlity"
)

func MetadataExample() {

	idp := saml.IdentityProvider{
		IsIdpInitiated:       false,
		Issuer:               "https://identity-provider.com/",
		IDPCert:              utitlity.GetIdpCertificate(),
		NameIdentifierFormat: saml.AttributeFormatUnspecified,
	}

	idp.AddSingleSignOnService(saml.MetadataBinding{
		Binding:  saml.HTTPPostBinding,
		Location: "https://identity-provider.com/saml/post",
	})

	idp.AddSingleSignOutService(saml.MetadataBinding{
		Binding:  saml.HTTPPostBinding,
		Location: "https://identity-provider.com/saml/post/logout",
	})

	// Add Organization Details. These are omitted from the XML if the struct is not defined
	idp.AddOrganization(saml.Organization{
		OrganizationDisplayName: "Monsters Inc",
		OrganizationName:        "Monsters",
		OrganizationURL:         "https://movies.disney.com/monsters-inc",
	})

	// Add a single Contact Person to Metadata
	idp.AddContactPerson(saml.ContactPerson{
		ContactType:  "Scarer",
		EmailAddress: "james.sullivan@monsters.inc",
		GivenName:    "James",
		SurName:      "Sullivan",
	})

	// It is also possible to add multiple `ContactPerson` at the same time.
	// Calling the `AddContactPerson` or `AddContactPersons` appends new
	// contact persons to the same slice
	persons := []saml.ContactPerson{
		{
			ContactType:  "Sidekick",
			EmailAddress: "michael.wazowski@monsters.inc",
			GivenName:    "Michael",
			SurName:      "Wazowski",
		},
	}
	idp.AddContactPersons(persons...)

	// Generate xml for IDP Metadata
	metadata, err := idp.MetaDataResponse()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("------------------Metadata------------------\n", metadata)
}
