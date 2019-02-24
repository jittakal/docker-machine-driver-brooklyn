// Copyright (C) 2016-2017 - All rights reserved.
package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/jittakal/docker-machine-driver-brooklyn/drivers/brooklyn"
)

func main() {
	plugin.RegisterDriver(brooklyn.NewDriver("", ""))
}
