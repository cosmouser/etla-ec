package main

import (
	"net/http"

	"github.com/cosmouser/etla-ec/actions"
	"github.com/cosmouser/etla-ec/config"
)

func main() {
	http.HandleFunc("/", actions.IndexHandler)
	http.HandleFunc("/getInfo", actions.APIHandler)
	http.ListenAndServe(config.Details.Port, nil)
}
