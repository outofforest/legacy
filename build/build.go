package build

import (
	"context"
)

func buildMe(ctx context.Context) error {
	return goBuildPkg(ctx, "build/cmd", "bin/build-legacy")
}
