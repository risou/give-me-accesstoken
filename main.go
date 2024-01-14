package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/risou/give-me-accesstoken/app"
)

var version = "0.1.0"

func main() {
	var option app.Option
	flag.StringVar(&option.ConfigFile, "f", "config.yml", "Config file")
	flag.StringVar(&option.ConfigSet, "c", "local", "Config Set")
	flag.BoolVar(&option.RawOutput, "raw", false, "Raw output")
	flag.BoolVar(&option.Version, "version", false, "Show version")

	flag.Parse()

	if option.Version {
		fmt.Printf("give-me-accesstoken version %s\n", version)
		os.Exit(0)
	}

	err := app.Run(option)
	if err != nil {
		log.Fatalf("Failed to run app: %s", err)
		os.Exit(1)
	}
}
