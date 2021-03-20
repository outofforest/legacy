package build

// Commands is a definition of commands available in build system
var Commands = map[string]interface{}{
	"tools/build":   buildMe,
	"dev/goimports": goImports,
	"dev/lint":      lint,
	"dev/test":      test,
	"build":         buildLegacy,
}
