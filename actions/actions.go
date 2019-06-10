package actions

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cosmouser/etla-ec/config"
)

// token is the current JWT for authenticating requests
var token *accessResponse

func init() {
	token = &accessResponse{}
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
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
