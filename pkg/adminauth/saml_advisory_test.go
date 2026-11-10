package adminauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// Exercise GO-2026-6909 at the real ACS parser and identity mapping boundary.
// Each malformed assertion is signed AFTER mutation, so refusal cannot be
// attributed to a broken signature. No SignatureVerifier override is used.
func TestSAML_Advisory6909_SignedAssertions(t *testing.T) {
	key := nil2key(t)
	cert := selfSignedTestCert(t, key, "advisory-idp.test")
	otherKey := nil2key(t)
	otherCert := selfSignedTestCert(t, otherKey, "untrusted-idp.test")
	server := fakeIDPMetadataServer(t, func(idp *saml.IdentityProvider) {
		idp.Key, idp.Certificate = key, cert
	})
	sp, err := NewSAMLSP(context.Background(), samlTestOptions(server.URL+"/metadata"))
	if err != nil {
		t.Fatal(err)
	}

	for _, anchor := range []string{"assertion", "response"} {
		t.Run(anchor, func(t *testing.T) {
			for _, tc := range []struct {
				name        string
				mutate      func(*etree.Element)
				parseReason string
				noIdentity  bool
				untrusted   bool
				tamper      bool
			}{
				{name: "valid"},
				{name: "missing_issuer", mutate: func(a *etree.Element) { a.RemoveChild(a.FindElement("saml:Issuer")) }, parseReason: "issuer is not"},
				{name: "missing_subject", mutate: func(a *etree.Element) { a.RemoveChild(a.FindElement("saml:Subject")) }, parseReason: "no Subject"},
				{name: "missing_conditions", mutate: func(a *etree.Element) { a.RemoveChild(a.FindElement("saml:Conditions")) }, parseReason: "no Conditions"},
				{name: "missing_confirmation_data", mutate: func(a *etree.Element) {
					c := a.FindElement("saml:Subject/saml:SubjectConfirmation")
					c.RemoveChild(c.FindElement("saml:SubjectConfirmationData"))
				}, parseReason: "no SubjectConfirmationData"},
				{name: "missing_name_id", mutate: func(a *etree.Element) {
					s := a.FindElement("saml:Subject")
					s.RemoveChild(s.FindElement("saml:NameID"))
				}, noIdentity: true},
				{name: "foreign_name_id", mutate: func(a *etree.Element) {
					n := a.FindElement("saml:Subject/saml:NameID")
					n.Space = "foreign"
					n.CreateAttr("xmlns:foreign", "urn:untrusted:identity")
					n.SetText("attacker@example.test")
				}, noIdentity: true},
				{name: "unqualified_name_id", mutate: func(a *etree.Element) {
					n := a.FindElement("saml:Subject/saml:NameID")
					n.Space = ""
					n.CreateAttr("xmlns", "")
				}, noIdentity: true},
				{name: "default_namespace_name_id", mutate: func(a *etree.Element) {
					n := a.FindElement("saml:Subject/saml:NameID")
					n.Space = ""
					n.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:assertion")
				}},
				{name: "foreign_name_id_does_not_override_valid_identity", mutate: func(a *etree.Element) {
					s := a.FindElement("saml:Subject")
					n := s.CreateElement("foreign:NameID")
					n.CreateAttr("xmlns:foreign", "urn:untrusted:identity")
					n.SetText("attacker@example.test")
				}},
				{name: "wrong_audience", mutate: func(a *etree.Element) {
					a.FindElement("saml:Conditions/saml:AudienceRestriction/saml:Audience").SetText("https://other-sp.test")
				}, parseReason: "AudienceRestriction does not contain"},
				{name: "wrong_recipient", mutate: func(a *etree.Element) {
					a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("Recipient", "https://other-sp.test/acs")
				}, parseReason: "Recipient is not"},
				{name: "wrong_request", mutate: func(a *etree.Element) {
					a.FindElement("saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData").CreateAttr("InResponseTo", "_another-flow")
				}, parseReason: "possible request IDs"},
				{name: "expired_conditions", mutate: func(a *etree.Element) {
					a.FindElement("saml:Conditions").CreateAttr("NotOnOrAfter", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
				}, parseReason: "Conditions is expired"},
				{name: "untrusted_signer", untrusted: true},
				{name: "tampered_signed_identity", tamper: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					signer, signingCert := key, cert
					if tc.untrusted {
						signer, signingCert = otherKey, otherCert
					}
					doc := signedAdvisoryResponse(t, sp, signer, signingCert, anchor, tc.mutate)
					if tc.tamper {
						doc.Root().FindElement("saml:Assertion/saml:Subject/saml:NameID").SetText("attacker@example.test")
					}
					raw, err := doc.WriteToBytes()
					if err != nil {
						t.Fatal(err)
					}
					form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(raw)}}
					req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, sp.SP.AcsURL.String(), strings.NewReader(form.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					assertion, err := sp.ParseACSResponse(req, "_tracked-request")
					if tc.parseReason != "" || tc.untrusted || tc.tamper {
						if err == nil || assertion != nil {
							t.Fatalf("invalid assertion accepted: assertion=%v error=%v", assertion, err)
						}
						if tc.parseReason != "" {
							var invalid *saml.InvalidResponseError
							if !errors.As(err, &invalid) || invalid.PrivateErr == nil || !strings.Contains(invalid.PrivateErr.Error(), tc.parseReason) {
								t.Fatalf("expected validation reason %q, got %#v", tc.parseReason, err)
							}
						}
						return
					}
					if err != nil {
						t.Fatalf("parse signed assertion: %#v", err)
					}
					email, err := AssertionEmail(assertion)
					if tc.noIdentity {
						if err == nil || email != "" || assertion.Subject.NameID != nil {
							t.Fatalf("missing or foreign NameID became a login identity: %q, %v", email, err)
						}
						return
					}
					if err != nil || email != "user@example.test" {
						t.Fatalf("identity changed: %q, %v", email, err)
					}
				})
			}
		})
	}
}

func signedAdvisoryResponse(t *testing.T, sp *SAMLSP, key *rsa.PrivateKey, cert *x509.Certificate, anchor string, mutate func(*etree.Element)) *etree.Document {
	t.Helper()
	now := time.Now().UTC()
	// All identities and keys are synthetic. The fixture is authored here and
	// exercises the same XML namespaces, trust metadata and request pairing as ACS.
	xml := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="_tracked-request">
<saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<saml:Assertion ID="_assertion" Version="2.0" IssueInstant="%s"><saml:Issuer>%s</saml:Issuer>
<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.test</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="_tracked-request" Recipient="%s" NotOnOrAfter="%s"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
</saml:Assertion></samlp:Response>`, now.Format(time.RFC3339), sp.SP.AcsURL.String(), sp.IDPEntityID(), now.Format(time.RFC3339), sp.IDPEntityID(), sp.SP.AcsURL.String(), now.Add(time.Minute).Format(time.RFC3339), now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), sp.SP.EntityID)
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	assertion := doc.Root().FindElement("saml:Assertion")
	// The assertion is also signed on its own, so its namespace must remain
	// defined when the signer copies it out of the response document.
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	if mutate != nil {
		mutate(assertion)
	}
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx.IdAttribute = "ID"
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	target := assertion
	if anchor == "response" {
		target = doc.Root()
	}
	signed, err := ctx.SignEnveloped(target)
	if err != nil {
		t.Fatal(err)
	}
	if anchor == "response" {
		doc.SetRoot(signed)
	} else {
		doc.Root().RemoveChild(assertion)
		doc.Root().AddChild(signed)
	}
	// Verify the serialized wire representation, as ACS does, rather than
	// the signer's in-memory tree (whose appended signature has no parent).
	wire, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	doc = etree.NewDocument()
	if err := doc.ReadFromBytes(wire); err != nil {
		t.Fatal(err)
	}
	signed = doc.Root()
	if anchor == "assertion" {
		signed = signed.FindElement("saml:Assertion")
	}
	validation := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	validation.IdAttribute = "ID"
	if _, err := validation.Validate(signed); err != nil {
		t.Fatalf("fixture signature is invalid before ACS: %v", err)
	}
	return doc
}
