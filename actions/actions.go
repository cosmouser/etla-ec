package actions

// token is the current JWT for authenticating requests
var token *accessResponse

func init() {
	token = &accessResponse{}
}
