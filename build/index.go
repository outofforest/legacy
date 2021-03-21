package build

// Commands is a definition of commands available in build system
var Commands = map[string]interface{}{
	"tools/build":   buildMe,
	"dev/goimports": goImports,
	"dev/lint":      lint,
	"dev/test":      test,
	"dev/build":     buildLegacyDev,
	"build":         buildLegacyProd,
	"public-key":    printPublicKey,
}
