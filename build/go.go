package build

import (
	"context"
	"os"
	"os/exec"

	"github.com/wojciech-malota-wojcik/build"
)

func runCmd(cmd *exec.Cmd) error {
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func goBuildPkg(ctx context.Context, pkg, out string) error {
	return runCmd(exec.CommandContext(ctx, "go", "build", "-o", out, "./"+pkg))
}

func lint(ctx context.Context, deps build.DepsFunc) error {
	deps(generateLegacy)
	return runCmd(exec.CommandContext(ctx, "golangci-lint", "run", "--config", "build/.golangci.yaml"))
}

func goImports(ctx context.Context) error {
	return runCmd(exec.CommandContext(ctx, "goimports", "-w", "."))
}

func test(ctx context.Context, deps build.DepsFunc) error {
	deps(generateLegacy)
	return runCmd(exec.CommandContext(ctx, "go", "test", "-count=1", "-race", "./..."))
}
