package main

import (
	"fmt"

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
	viper.SetDefault("outputFile", "out.json")

	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore error if desired
			panic(fmt.Errorf("config file not found: %s \n", err))
		} else {
			// Config file was found but another error was produced
			panic(fmt.Errorf("Fatal error config file: %s \n", err))
		}
	}

	log.Debugf("Parsing %s file for %s cloud, result will be written to %s",
		viper.GetString("policyFile"),
		viper.GetString("cloud"),
		viper.GetString("outputFile"))

	p, err := parser.NewParser(viper.GetString("cloud"), viper.GetString("policyFile"),
		viper.GetBool("urlEscaped"), viper.GetString("outputFile"))
	if err != nil {
		panic(fmt.Errorf("Error instantiating parser: %s", err))
	}

	err = p.Parse()
	if err != nil {
		panic(fmt.Errorf("Error parsing the policy: %s", err))
	}

	err = p.Write()
	if err != nil {
		panic(fmt.Errorf("Error writing the output file: %s", err))
	}

}
