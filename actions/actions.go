package actions

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/badoux/checkmail"
	"github.com/cosmouser/etla-ec/config"
	log "github.com/sirupsen/logrus"
)

// umtoken is the current JWT for authenticating requests
var umToken *accessResponse

func init() {
	umToken = &accessResponse{}
}

// APIHandler is handles all external calls to the API
func APIHandler(w http.ResponseWriter, r *http.Request) {
	ra := r.Header.Get("X-Real-IP")
	if ra == "" {
		ra = r.RemoteAddr
	}
	rURI, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		log.Fatal(err)
	}
	query := rURI.Query()
	switch r.Method {
	case "GET":
		if err := checkmail.ValidateFormat(query.Get("uid")); err != nil {
			log.WithFields(log.Fields{
				"remoteAddr": ra,
				"uid":        query.Get("uid"),
			}).Error(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := getUserInfo(query.Get("uid"), umToken)
		if err != nil {
			log.WithFields(log.Fields{
				"remoteAddr": ra,
				"uid":        query.Get("uid"),
			}).Error(err.Error())
			http.Error(w, "request to adobe was not successful", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		log.WithFields(log.Fields{
			"remoteAddr": ra,
			"uid":        query.Get("uid"),
		}).Info("response delivered")
		slurp, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal("unable to read response from adobe", err)
		}
		w.Write(slurp)
	}
	return
}

func getUserInfo(userString string, token *accessResponse) (*http.Response, error) {
	var httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
	// GET /v2/usermanagement/organizations/{orgId}/users/{userString}
	// Retrieves the details of a single user within a specified organization
	// identified by email address or username and domain. Successful queries
	// return a 200 response whose body is a single JSON structure containing
	// the user information.
	resourceURI := fmt.Sprintf("https://%s%s/organizations/%s/users/%s",
		config.Details.Server["Host"],
		config.Details.Server["Endpoint"],
		config.Details.Enterprise["OrgID"],
		userString,
	)
	req, err := http.NewRequest("GET", resourceURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("x-api-key", config.Details.Enterprise["APIKey"])
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", umToken.AccessToken))
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	// renews the token if its expired and resends the getUserInfo request
	if resp.StatusCode == 401 {
		umToken.renew()
		resp, err = httpClient.Do(req)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}
