package main

import (
	"log"

	"github.com/wojciech-malota-wojcik/legacy/secrets"
	"github.com/wojciech-malota-wojcik/legacy/util"
)

func main() {
	util.WorkingDir(1)

	if err := secrets.Generate(); err != nil {
		log.Fatal(err)
	}
}
