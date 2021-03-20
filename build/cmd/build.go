package main

import (
	"context"
	"github.com/wojciech-malota-wojcik/legacy/util"
	"log"

	"github.com/wojciech-malota-wojcik/build"
	"github.com/wojciech-malota-wojcik/ioc"
	me "github.com/wojciech-malota-wojcik/legacy/build"
)

func main() {
	util.WorkingDir(1)
	ctx := context.Background()
	c := ioc.New()
	c.Singleton(func() context.Context {
		return ctx
	})
	exec := build.NewIoCExecutor(me.Commands, c)
	if build.Autocomplete(exec) {
		return
	}
	if err := build.Do(ctx, "Legacy", exec); err != nil {
		log.Fatal(err)
	}
}
