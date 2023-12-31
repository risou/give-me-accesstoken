package main

import (
	"flag"
	"log"
	"os"

	"github.com/risou/give-me-accesstoken/app"
)

func main() {
	var option app.Option
	flag.StringVar(&option.ConfigFile, "f", "config.yml", "Config file")
	flag.StringVar(&option.ConfigSet, "c", "local", "Config Set")
	flag.BoolVar(&option.RawOutput, "raw", false, "Raw output")

	flag.Parse()

	err := app.Run(option)
	if err != nil {
		log.Fatalf("Failed to run app: %s", err)
		os.Exit(1)
	}
}
