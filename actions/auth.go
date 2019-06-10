package actions

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/cosmouser/etla-ec/config"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	log "github.com/sirupsen/logrus"
)

var serviceProvider *saml2.SAMLServiceProvider

var store = sessions.NewCookieStore(securecookie.GenerateRandomKey(32))
var spKeyStore *keyStore

type keyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *keyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

// SAMLCallback receives assertions from the IDP.
func SAMLCallback(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	assertionInfo, err := serviceProvider.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if assertionInfo.WarningInfo.InvalidTime {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if assertionInfo.WarningInfo.NotInAudience {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	values := make(map[string]bool)
	var principalName string
	for _, val := range assertionInfo.Values {
		if val.FriendlyName == "eduPersonAffiliation" {
			for _, v := range val.Values {
				values[v.Value] = true
			}
		}
		if val.FriendlyName == "eduPersonPrincipalName" {
			for _, v := range val.Values {
				principalName = v.Value
			}
		}
	}
	affiliations := []string{}
	for k := range values {
		affiliations = append(affiliations, k)
	}
	if principalName != "" {
		session, _ := store.Get(r, "etla-ec_session")
		log.WithFields(log.Fields{
			"principal":    principalName,
			"affiliations": affiliations,
		}).Info("user logged in")

		// Set user as authenticated
		session.Values["authenticated"] = true
		session.Values["principal"] = principalName
		session.Save(r, w)
		http.Redirect(w, r, config.Details.ExternalURL+"/", http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusForbidden)
	return
}

// AuthMiddleware checks if the user is logged in.
// If they are not, it redirects them to the login page.
func AuthMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ra := r.Header.Get("X-Real-IP")
		if ra == "" {
			ra = r.RemoteAddr
		}
		session, err := store.Get(r, "jackstat_session")
		if err != nil {
			http.Redirect(w, r, config.Details.ExternalURL+"/login", 302)
			log.WithFields(log.Fields{
				"error":      err,
				"remoteAddr": ra,
			}).Info()
			return
		}
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, config.Details.ExternalURL+"/login", 302)
			log.WithFields(log.Fields{
				"error":      "user not authenticated",
				"remoteAddr": ra,
			}).Info()
			return
		}

		log.WithFields(log.Fields{
			"remoteAddr": ra,
			"principal":  session.Values["principal"],
			"resource":   r.URL.Path + "?" + r.URL.RawQuery,
		}).Info("accessed")
		handler.ServeHTTP(w, r)
	})
}

// RedirectToIDP takes the place of a login form in a SAMLV2 context
func RedirectToIDP(w http.ResponseWriter, r *http.Request) {
	authURL, err := serviceProvider.BuildAuthURL(config.Details.AudienceURI)
	if err != nil {
		panic(err)
	}
	http.Redirect(w, r, authURL, 302)
	return
}

// LoadSP reloads the service provider
func LoadSP() {
	res, err := http.Get(config.Details.IDPMetadataURL)
	if err != nil {
		panic(err)
	}

	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		panic(err)
	}

	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic(fmt.Errorf("metadata certificate(%d) must not be empty", idx))
			}
			trimmedData := strings.TrimSpace(xcert.Data)
			certData, err := base64.StdEncoding.DecodeString(trimmedData)
			if err != nil {
				panic(err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				panic(err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	var idpSSOURL string
	for _, v := range metadata.IDPSSODescriptor.SingleSignOnServices {
		if v.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			idpSSOURL = v.Location
			log.WithFields(log.Fields{
				"IdentityProviderSSOURL": v.Location,
			}).Info("renewing saml configuration")
			break
		}
	}
	if idpSSOURL == "" {
		panic("cannot find location with binding: urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	}

	serviceProvider = &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:         idpSSOURL,
		IdentityProviderIssuer:         metadata.EntityID,
		ServiceProviderIssuer:          config.Details.ServiceProviderIssuer,
		AssertionConsumerServiceURL:    config.Details.ServiceProviderIssuer + config.Details.AssertionConsumerServiceURL,
		SignAuthnRequests:              true,
		SignAuthnRequestsAlgorithm:     dsig.RSASHA256SignatureMethod,
		SignAuthnRequestsCanonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
		AudienceURI:                    config.Details.AudienceURI,
		IDPCertificateStore:            &certStore,
		SPKeyStore:                     spKeyStore,
	}
}

// ExposeMetadata displays the metadata for the application
func ExposeMetadata(w http.ResponseWriter, r *http.Request) {
	meta, err := serviceProvider.Metadata()
	if err != nil {
		http.Error(w, "could not generate metadata", http.StatusInternalServerError)
		return
	}
	xmldata, err := xml.MarshalIndent(meta, "", "    ")
	if err != nil {
		http.Error(w, "could not marshal metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, string(xmldata))
	return
}

// InitKeyStore loads the keys for creating the service provider.
func InitKeyStore() {
	// key store generation
	f, err := os.Open(config.Details.PrivateKeyPath)
	if err != nil {
		panic(err)
	}
	privData, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	f.Close()
	privBlock, _ := pem.Decode(privData)
	pkr, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		panic(err)
	}
	pk := pkr.(*rsa.PrivateKey)
	f, err = os.Open(config.Details.PublicCertPath)
	if err != nil {
		panic(err)
	}
	pubData, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	f.Close()
	pubBlock, _ := pem.Decode(pubData)
	if err != nil {
		panic(err)
	}
	spKeyStore = &keyStore{
		privateKey: pk,
		cert:       pubBlock.Bytes,
	}
}
