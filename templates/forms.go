package templates

import "html/template"

func SAMLResponsePostForm() *template.Template {
	return template.Must(template.New("samlresponse-form").Parse(`<html>` +
		`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
		`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Continue" />` +
		`</form>` +
		`<script>document.getElementById('SAMLSubmitButton').style.visibility='hidden';</script>` +
		`<script>document.getElementById('SAMLResponseForm').submit();</script>` +
		`</html>`))
}
