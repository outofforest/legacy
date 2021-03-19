package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ridge/must"
	"github.com/wojciech-malota-wojcik/legacy/secrets"
)

func main() {
	changeWorkingDir()

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

func changeWorkingDir() {
	must.OK(os.Chdir(filepath.Dir(must.String(filepath.EvalSymlinks(must.String(os.Executable()))))))
}
