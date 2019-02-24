// Package brooklyn Copyright (C) 2016-2017 - All rights reserved.
package brooklyn

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/apache/brooklyn-client/cli/api/application"
	"github.com/apache/brooklyn-client/cli/api/entity_effectors"
	"github.com/apache/brooklyn-client/cli/api/entity_sensors"
	"github.com/apache/brooklyn-client/cli/api/locations"
	"github.com/apache/brooklyn-client/cli/models"
	"github.com/apache/brooklyn-client/cli/net"
	"github.com/docker/machine/libmachine/log"
)

const (
	// HostSSHAddressSensor is sensor information for host address
	HostSSHAddressSensor       = "host.sshAddress"
	HostSSHSubnetAddressSensor = "host.subnet.address"
)

// CatalogByRegex returns catalog which can be filter by regular expression
func CatalogByRegex(network *net.Network, regex string) ([]models.CatalogItemSummary, error) {
	url := fmt.Sprintf("/v1/catalog/applications/?regex=%s&allVersions=false", regex)
	var response []models.CatalogItemSummary
	body, err := network.SendGetRequest(url)
	if err != nil {
		return response, err
	}
	err = json.Unmarshal(body, &response)
	return response, err
}

// CatalogByName returns catalog with fixed symbolicName and version
func CatalogByName(network *net.Network, symbolicName, version string) (models.CatalogItemSummary, error) {
	url := fmt.Sprintf("/v1/catalog/applications/%s/%s", symbolicName, version)
	var response models.CatalogItemSummary
	body, err := network.SendGetRequest(url)
	if err != nil {
		return response, err
	}
	err = json.Unmarshal(body, &response)
	return response, err
}

// Delete invokes expunge request for application.
func Delete(network *net.Network, application string) (models.TaskSummary, error) {
	url := fmt.Sprintf("/v1/applications/%s/entities/%s/expunge?release=true", application, application)
	var response models.TaskSummary
	body, err := network.SendEmptyPostRequest(url)
	if err != nil {
		return response, err
	}
	err = json.Unmarshal(body, &response)
	return response, err
}

// DescendantsSSHHostSubnetAddress returns SSH host information of node.
func DescendantsSSHHostSubnetAddress(network *net.Network, applicationID string) (string, error) {
	sensor, err := application.DescendantsSensor(network, applicationID, HostSSHSubnetAddressSensor)
	m := map[string]string{}
	var sshHostSubnetAddress string
	if err != nil {
		return sshHostSubnetAddress, err
	}

	err = json.Unmarshal([]byte(sensor), &m)
	if err != nil {
		return sshHostSubnetAddress, err
	}
	log.Debug(m)

	for key := range m {
		sshHostSubnetAddress = m[key]
		break
	}
	return sshHostSubnetAddress, nil
}

// DescendantsSSHHostAndPortSensor returns SSH host information of node.
func DescendantsSSHHostAndPortSensor(network *net.Network, applicationID string) (SSHHostAddress, error) {
	sensor, err := application.DescendantsSensor(network, applicationID, HostSSHAddressSensor)
	m := map[string]SSHHostAddress{}
	var sshHostAddress SSHHostAddress
	if err != nil {
		return sshHostAddress, err
	}

	err = json.Unmarshal([]byte(sensor), &m)
	if err != nil {
		return sshHostAddress, err
	}
	log.Debug(m)

	for key := range m {
		sshHostAddress = m[key]
		break
	}
	return sshHostAddress, nil
}

// GetNodeID return node ID.
func GetNodeID(network *net.Network, applicationID string) (string, error) {
	sensorInfo, err := application.DescendantsSensor(network, applicationID, HostAddressSensorName)
	var nodeID string

	m := map[string]string{}
	if err != nil {
		return nodeID, err
	}

	err = json.Unmarshal([]byte(sensorInfo), &m)
	if err != nil {
		return nodeID, err
	}
	for key := range m {
		log.Info("Key: ", key)
		nodeID = key
		break
	}
	return nodeID, nil
}

// GetNodeState returns node current state
func GetNodeState(network *net.Network, applicationID, entityID string) (string, error) {
	serviceState, err := entity_sensors.SensorValue(network, applicationID, entityID, ServiceStateSensorName)

	if err != nil {
		return "", err
	} else if state, ok := serviceState.(string); ok {
		return state, nil
	}

	return "UNKNOWN", nil
}

// DescendantsSensor returns sensor information of decendant node.
func DescendantsSensor(network *net.Network, applicationID string, sensor string) (map[string]int, error) {
	sensor, err := application.DescendantsSensor(network, applicationID, sensor)
	m := map[string]int{}
	if err != nil {
		return m, err
	}

	err = json.Unmarshal([]byte(sensor), &m)
	if err != nil {
		return m, err
	}
	log.Debug(m)
	return m, nil
}

// LocationExists validates location exists or not
func LocationExists(network *net.Network, locationName string) (string, error) {
	locations, err := locations.LocationList(network)

	var locationID string
	if err != nil {
		return locationID, err
	}

	for _, location := range locations {
		if location.Name == locationName {
			return locationID, nil
		}
	}
	return locationID, errors.New("Location with specified name does not exists.")
}

// TriggerStart trigger start
func TriggerStart(network *net.Network, applicationID string, entityID string) error {
	params := []string{}
	args := []string{}
	_, err := entity_effectors.TriggerEffector(network, applicationID, entityID, "start", params, args)
	return err
}

// TriggerStop triggers stop
func TriggerStop(network *net.Network, applicationID string, entityID string) error {
	params := []string{"stopProcessMode", "stopMachineMode"}
	args := []string{"ALWAYS", "NEVER"}
	_, err := entity_effectors.TriggerEffector(network, applicationID, entityID, "stop", params, args)
	return err
}

// TriggerRestart triggers restart.
func TriggerRestart(network *net.Network, applicationID string, entityID string) error {
	params := []string{"restartChildren", "restartMachine"}
	args := []string{"true", "false"}
	_, err := entity_effectors.TriggerEffector(network, applicationID, entityID, "restart", params, args)
	return err
}
