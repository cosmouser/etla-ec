package actions

// accessResponse is the json body of the response from
// requestAccess. It contains the accessToken that is used
// for authorizing User Management API requests.
type accessResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// token is the current JWT for authenticating requests
var token *accessResponse

func init() {
	token = &accessResponse{}
}
