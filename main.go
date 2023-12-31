package main

import (
	"flag"
	"github.com/risou/give-me-accesstoken/app"
	"log"
	"os"
)

func main() {
	var option app.Option
	flag.StringVar(&option.ConfigFile, "f", "config.yml", "Config file")
	flag.StringVar(&option.ConfigSet, "c", "local", "Config Set")

	flag.Parse()

	err := app.Run(option)
	if err != nil {
		log.Fatalf("Failed to run app: %s", err)
		os.Exit(1)
	}
}
