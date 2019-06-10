package actions

import (
	"fmt"
	"html/template"
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
	checkToken()
}

// APIHandler is handles all external calls to the API
func APIHandler(w http.ResponseWriter, r *http.Request) {
	checkToken()
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
		slurp, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal("unable to read response from adobe", err)
		}
		w.Write(slurp)
		log.WithFields(log.Fields{
			"remoteAddr": ra,
			"uid":        query.Get("uid"),
		}).Info("response delivered")
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
	return resp, nil
}

// IndexHandler serves the home page with the form for submitting internal requests to etla-ec
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	var data = struct {
		ExternalURL string
	}{
		ExternalURL: config.Details.ExternalURL,
	}
	if err := indexTemplate.Execute(w, &data); err != nil {
		log.Error(err)
	}
	return
}

var indexTemplate = template.Must(template.New("1").Parse(`<!DOCTYPE html>
<html>
  <head>
	<title>ETLA Entitlement Checker</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
	<link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous"> 
    <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>  </head>
  <body class="container-fluid">
	<div class="row">
	  <div class="col-lg-12">
		<h1>ETLA Entitlement Checker</h1>
		<form id="checker">
		  <div class="form-group"><label for="uid">Email of user:</label>
		  <input type="text" class="form-control" id="uid" name="uid" value="cosmo@ucsc.edu"></div>
		  <button type="submit" class="btn btn-primary">Submit</button>
		</form>
		<br>
		<div class="well" id="results">Results will show here</div>
		<script>
		  $("#checker").submit(function(e) {
			var form = $(this);
		    $.ajax({
			  type: "GET",
			  url: '{{.ExternalURL}}/getInfo?' + form.serialize(),
			  success: function(data) {
				  var out = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
				$("#results").html(out);
			  },
			  error: function(jqxhr) {
				$("#results").text(jqxhr.responseText);
			  },
			  beforeSend: function(xhr, settings) {
				xhr.setRequestHeader('Accept', 'application/json');
			  }
			});
			e.preventDefault();
		  });
	  </script>
	  </div>
	</div>
  </body>
</html>
`))
