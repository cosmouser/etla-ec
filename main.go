package main

import (
	"net/http"
	"time"

	"github.com/cosmouser/etla-ec/actions"
	"github.com/cosmouser/etla-ec/config"
)

func main() {
	actions.InitKeyStore()
	go func() {
		for {
			actions.LoadSP()
			time.Sleep(time.Hour * 24)
		}
	}()
	http.HandleFunc("/", actions.IndexHandler)
	http.HandleFunc("/getInfo", actions.APIHandler)
	http.HandleFunc("/login", actions.RedirectToIDP)
	http.HandleFunc("/metadata", actions.ExposeMetadata)
	http.HandleFunc(config.Details.AssertionConsumerServiceURL, actions.SAMLCallback)
	http.ListenAndServe(config.Details.Port, nil)
}
