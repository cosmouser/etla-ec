package actions

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cosmouser/etla-ec/config"
)

// token is the current JWT for authenticating requests
var token *accessResponse

func init() {
	token = &accessResponse{}
}

func sendRequest(body string, token *accessResponse) (*http.Response, error) {
	var httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
	bodyReader := strings.NewReader(body)
	resourceURI := fmt.Sprintf("https://%s%s/action/%s",
		config.Details.Server["Host"],
		config.Details.Server["Endpoint"],
		config.Details.Enterprise["OrgID"],
	)
	req, err := http.NewRequest("POST", resourceURI, bodyReader)
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
