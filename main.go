package main

import (
	"log"

	"github.com/jeandreh/iam-snitch/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
