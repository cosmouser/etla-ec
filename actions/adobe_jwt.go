package actions

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/cosmouser/etla-ec/config"
	jwt "github.com/dgrijalva/jwt-go"
)

// accessResponse is the json body of the response from
// requestAccess. It contains the accessToken that is used
// for authorizing User Management API requests.
type accessResponse struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	ExpiresOn   string
}

func checkToken() {
	var err error
	if umToken == nil {
		umToken = &accessResponse{ExpiresOn: "0"}
	}
	expDate, err := strconv.Atoi(umToken.ExpiresOn)
	if err != nil {
		log.Fatal(err)
	}
	if time.Unix(int64(expDate), 0).Before(time.Now()) {
		umToken.renew()
	}
}
func generateJWT() string {
	signBytes, err := ioutil.ReadFile(config.Details.Enterprise["PrivKeyPath"])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	mySigningKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}

	aud := fmt.Sprintf("https://%s/c/%s", config.Details.Server["ImsHost"], config.Details.Enterprise["APIKey"])
	dur := time.Second * 60 * 60 * 24
	exp := time.Now().Add(dur).Unix()

	type myCustomClaims struct {
		EntUserSdk bool `json:"https://ims-na1.adobelogin.com/s/ent_user_sdk"`
		jwt.StandardClaims
	}
	claims := myCustomClaims{
		true,
		jwt.StandardClaims{
			Audience:  aud,
			ExpiresAt: exp,
			Issuer:    config.Details.Enterprise["OrgID"],
			Subject:   config.Details.Enterprise["TechAcct"],
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(mySigningKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
	vals := url.Values{}
	vals.Set("client_id", config.Details.Enterprise["APIKey"])
	vals.Set("client_secret", config.Details.Enterprise["ClientSecret"])
	vals.Set("jwt_token", ss)
	return vals.Encode()
}

func requestAccess(body string) (*accessResponse, error) {
	var httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
	bodyReader := strings.NewReader(body)
	resourceURI := fmt.Sprintf("https://%s%s", config.Details.Server["ImsHost"], config.Details.Server["ImsEndpointJwt"])
	req, err := http.NewRequest("POST", resourceURI, bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Cache-Control", "no-cache")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return nil, err
	}
	defer resp.Body.Close()
	output, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return nil, err
	}
	var accResp accessResponse
	err = json.Unmarshal(output, &accResp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return nil, err
	}
	return &accResp, nil
}

// renew renews the token
func (token *accessResponse) renew() {
	var err error
	generatedJWT := generateJWT()
	newToken, err := requestAccess(generatedJWT)
	if err != nil {
		log.Printf("%s\n", err)
	}
	token.TokenType = newToken.TokenType
	token.AccessToken = newToken.AccessToken
	token.ExpiresIn = newToken.ExpiresIn
	token.ExpiresOn = strconv.Itoa(int(time.Now().Add(time.Millisecond * time.Duration(token.ExpiresIn)).Unix()))
	log.WithFields(log.Fields{
		"TokenType":   token.TokenType,
		"AccessToken": token.AccessToken,
		"ExpiresIn":   token.ExpiresIn,
		"ExpiresOn":   token.ExpiresOn,
	}).Info("token renewed")
}
