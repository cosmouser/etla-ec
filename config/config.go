package config

import (
	"flag"
	"log"

	"github.com/BurntSushi/toml"
)

// Config data provides etla-ec with credentials for talking with Adobe's UMAPI
type Config struct {
	Server     map[string]string
	Enterprise map[string]string
}

// Server map
//      Host           string
//      Endpoint       string
//      ImsHost        string
//      ImsEndpointJwt string

// Enterprise map
//      Domain         string
//      OrgID          string
//      APIKey         string
//      ClientSecret   string
//      TechAcctstring string
//      PrivKeyPath    string

// Details is exported for use in other parts of etla-ec
var Details Config

func init() {
	var err error
	configPath := flag.String("config", "./config/test_config.toml", "use -config to specify the config file to load")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("please use -config to specify a config file")
	}
	_, err = toml.DecodeFile(*configPath, &Details)
	if err != nil {
		log.Fatal("could not load config at:", *configPath)
	}
}
