package main

import (
	"fmt"
	"github.com/wojciech-malota-wojcik/legacy/secrets"
	"os"
)

func main() {
	var err error
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
	}()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "secrets":
			err = secrets.Generate()
		}
		return
	}
	err = secrets.Integrate()
	//err = yubi.Test()
}
