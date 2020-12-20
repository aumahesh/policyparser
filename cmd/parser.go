package main

import (
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/aumahesh/policyparser/pkg/parser"
)

func main() {
	log.SetLevel(log.DebugLevel)

	log.Debugf("Hello, World!")

	viper.SetDefault("cloud", "aws")
	viper.SetDefault("policyFile", "awspolicy.json")
	viper.SetDefault("urlEscaped", true)

	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			panic(fmt.Errorf("config file not found: %s \n", err.Error()))
		} else {
			// Config file was found but another error was produced
			panic(fmt.Errorf("Fatal error config file: %s \n", err.Error()))
		}
	}

	log.Debugf("Parsing %s file for %s cloud",
		viper.GetString("policyFile"),
		viper.GetString("cloud"))

	r, err := os.Open(viper.GetString("policyFile"))
	if err != nil {
		panic(fmt.Errorf("Error opening file: %s", err.Error()))
	}
	policyText, err := ioutil.ReadAll(r)
	if err != nil {
		panic(fmt.Errorf("Error reading file: %s", err.Error()))
	}

	log.Debugf("%s", policyText)

	p, err := parser.NewParser(viper.GetString("cloud"), string(policyText), viper.GetBool("urlEscaped"))
	if err != nil {
		panic(fmt.Errorf("Error instantiating parser: %s", err.Error()))
	}

	err = p.Parse()
	if err != nil {
		panic(fmt.Errorf("Error parsing the policy: %s", err.Error()))
	}

	policies, err := p.GetPolicy()
	if err != nil {
		panic(fmt.Errorf("Error writing the output file: %s", err.Error()))
	}

	for index, pol := range policies {
		log.Infof("pol #%d: %+v", index, pol)
	}
}
