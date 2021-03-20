package util

import (
	"os"
	"path/filepath"

	"github.com/ridge/must"
)

// WorkingDir sets working directory by going up the tree by specified number of steps from the directory where executable exists
func WorkingDir(steps int) {
	exePath := must.String(filepath.EvalSymlinks(must.String(os.Executable())))
	steps += 1
	for i := 0; i < steps; i++ {
		exePath = filepath.Dir(exePath)
	}
	must.OK(os.Chdir(exePath))
}
