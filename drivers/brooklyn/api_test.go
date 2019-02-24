// Copyright (C) 2016-2017 - All rights reserved.
package brooklyn

import (
	"testing"

	"github.com/apache/brooklyn-client/cli/net"
	"github.com/docker/machine/libmachine/log"
)

var (
	network = net.NewNetwork("http://brooklyn-test", "user", "password", false)
)

func TestDelete(t *testing.T) {
	sshHostAddress, err := DescendantsSSHHostAndPortSensor(network, "s0ZNhmV9")

	if err != nil {
		t.Fail()
	}

	log.Info(sshHostAddress)
}

func TestSensor(t *testing.T) {
	sshHostAddress, err := DescendantsSensor(network, "sdpxTJF2", MappedPortSensorName)

	if err != nil {
		t.Fail()
	}

	log.Info(sshHostAddress)
}

func TestCatalogByRegex(t *testing.T) {
	catalogs, err := CatalogByRegex(network, "com.apache.brooklyn.ubuntu")
	log.Info(catalogs)
	if err != nil || len(catalogs) <= 0 {
		t.Fail()
	}
}
