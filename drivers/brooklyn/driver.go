// Package brooklyn Copyright (C) 2016-2017 - All rights reserved.
package brooklyn

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"

	"errors"

	"bytes"
	"text/template"

	"io/ioutil"

	"strings"

	"regexp"
	"time"

	"github.com/apache/brooklyn-client/cli/api/application"
	"github.com/apache/brooklyn-client/cli/api/server"
	"github.com/apache/brooklyn-client/cli/net"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

const (
	driverName     = "brooklyn"
	defaultSSHUser = "brooklyn"
	defaultSSHPort = 22
)

const (
	// Small T-shirt size
	Small = "small"
	// Medium T-shirt size
	Medium = "medium"
	// Large T-shirt size
	Large = "large"
	// XLarge T-shirt size
	XLarge = "xlarge"
	// XXLarge T-shirt size
	XXLarge = "xxlarge"
	// XXXLarge T-shirt size
	XXXLarge = "xxxlarge"
	// MappedPortSensorName sensor key
	MappedPortSensorName = "mapped.portPart.dockerhost.port"
	// HostAddressSensorName sensor key
	HostAddressSensorName = "host.address"
	// ServiceStateSensorName sensor key
	ServiceStateSensorName = "service.state"
	// NewRelic as a monitoring tool
	NewRelic = "newrelic"
	// Dynatrace as a monitoring tool
	Dynatrace = "dynatrace"
	// LogEntries as a log management tool
	LogEntries = "logentries"
	// None as a default value
	None = "none"
)

var (
	dockerPort = 2376
	//swarmPort  = 3376

	defaultBrooklynBaseURL = "http://localhost:8081"
	//defaultOpenPorts = "tomcat.port: 8080,web.port: 80,ssl.port: 443"
	openPortsRegx = regexp.MustCompile(`([A-Za-z])\w+[.]port[:][\ ][0-9]{1,5}`)
	osRegx        = regexp.MustCompile(`([a-zA-z])\w+[:][0-9]{1,2}([.][0-9]{1,2})?`)

	brooklynBaseURL                  = "brooklyn-base-url"
	brooklynUser                     = "brooklyn-user"            // mandatory
	brooklynPassword                 = "brooklyn-password"        // mandatory
	brooklynTargetLocation           = "brooklyn-target-location" // mandatory
	brooklynSkipOS                   = "brooklyn-skip-os"
	brooklynCatalogID                = "brooklyn-catalog-id"
	brooklynTargetOS                 = "brooklyn-target-os"
	brooklynTemplateSize             = "brooklyn-template-size"
	brooklynOpenPorts                = "brooklyn-open-ports"
	brooklynUsePrivateIP             = "brooklyn-use-private-ip"
	brooklynMonitoringTool           = "brooklyn-monitoring-tool"
	brooklynLogManagementTool        = "brooklyn-log-management-tool"
	brooklynCustomStorage            = "brooklyn-custom-storage"
	brooklynCustomStorageSize        = "brooklyn-custom-storage-size"
	brooklynRhelSubscriptionID       = "brooklyn-rhel-subscription-id"
	brooklynRhelSubscriptionPassword = "brooklyn-rhel-subscription-password"

	defaultCatalogID         = "com.apache.brooklyn.rancher.dockerhost"
	defaultOperatingSystem   = "ubuntu:16.04"
	defaultTemplateSize      = Medium
	templateSizes            = []string{Small, Medium, Large, XLarge, XXLarge, XXXLarge}
	monitoringTools          = []string{NewRelic, Dynatrace, None}
	defaultMonitoringTool    = None
	logManagementTools       = []string{LogEntries, None}
	defaultLogManagementTool = None

	errorMissingUser              = errors.New("Brooklyn user requires use the --brooklyn-user option")
	errorMissingPassword          = errors.New("Brooklyn password requires use the --brooklyn-password option")
	errorMissingLocation          = errors.New("Brooklyn target location requires use the --brooklyn-target-location option")
	errorInvalidOpenPorts         = errors.New("Invalid input request to open ports, format is > web.port: 2345,tomcat.port: 8080 < etc")
	errorInvalidTemplateSize      = errors.New("Specified template size not supported, available options are small, medium, large, xlarge, xxlarge and xxxlarge")
	errorNotStarting              = errors.New("Brooklyn application state should be Starting: Maximum number of retries (10) exceeded")
	errorInvalidOS                = errors.New("Specified operating system format is not supported, it shouble ubuntu:16.04 or centos:7.2 etc")
	errorCatalogNotExists         = errors.New("Specified catalog does not exists")
	errorInvalidMonitoringTool    = errors.New("Specified monitoring tool is not supported")
	errorInvalidLogManagementTool = errors.New("Specified log management tool is not supported")
	errorInvalidCustomStorageSize = errors.New("Invalid storage specified, it must be greater than 0")
)

// Driver structure
type Driver struct {
	*drivers.BaseDriver
	BrooklynClient       *net.Network
	Application          *Application
	ID                   string
	ApplicationID        string
	NodeID               string         `json:",omitempty"`
	SSHHostAddress       SSHHostAddress `json:",omitempty"`
	SSHHostSubnetAddress string         `json:",omitempty"`
	UsePrivateIP         bool           `json:",omitempty"`
}

// NewDriver return *Driver
func NewDriver(machineName, storePath string) *Driver {
	id := generateID()

	driver := &Driver{
		ID: id,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: machineName,
			StorePath:   storePath,
		},
	}
	return driver
}

// Template for DockerHost
const dockerHostAppTmpl = `name: {{.Application.Name}}
location: {{.Application.Location}}
services:
  - type: {{.Application.Type}}
    brooklyn.config:
      dockerhost.port: 2376{{if .SwarmMaster}}
      swarmhost.port: 3376{{end}}{{if .Application.Skip}}
      brooklyn.os.utility.skip: {{.Application.Skip}}{{else}}
      brooklyn.os.name: {{.Application.OsName}}
      brooklyn.os.version: '{{.Application.OsVersion}}'{{if .Application.CustomStorage}}
      brooklyn.template.hdd.size:  {{.Application.CustomStorageSize}}{{end}}
      brooklyn.template.size: {{.Application.TemplateSize}}{{end}}{{if .Application.NewRelic}}
      brooklyn.installNewRelic: {{.Application.NewRelic}}{{end}}{{if .Application.Dynatrace}}
      brooklyn.installRuxit: {{.Application.Dynatrace}}{{end}}{{if .Application.LogEntries}}
      brooklyn.installLogEntriesAgent: {{.Application.LogEntries}}{{end}}{{if .Application.RhelSubscriptionID}}
      brooklyn.rhel.subscripton.id: {{.Application.RhelSubscriptionID}}{{end}}{{if .Application.RhelSubscriptionPassword}}
      brooklyn.rhel.subscription.password: {{.Application.RhelSubscriptionPassword}}{{end}}
      brooklyn.sshUserKey: {{.Application.SSHUserKey}}{{range $_, $val := .Application.OpenPorts}}
      {{$val}}{{end}}
      `

func applicationYaml(driver *Driver) ([]byte, error) {
	log.Debugf("Calling .applicationYaml()")
	// Create a new template and parse the application into it.
	var t *template.Template
	t = template.Must(template.New("driver").Parse(dockerHostAppTmpl))
	var appYml bytes.Buffer
	err := t.Execute(&appYml, driver)
	log.Infof(appYml.String())
	var app []byte
	if err != nil {
		return app, err
	}
	return appYml.Bytes(), nil
}

// generateID generates random id.
func generateID() string {
	log.Debugf("Calling .generateID()")
	rb := make([]byte, 10)
	_, err := rand.Read(rb)
	if err != nil {
		log.Warnf("Unable to generate id: %s", err)
	}

	h := md5.New()
	io.WriteString(h, string(rb))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// contains validate element exists in slice or not.
func contains(element string, elements []string) bool {
	log.Debugf("Calling .contains()")
	for _, s := range elements {
		if element == s {
			return true
		}
	}
	return false
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	log.Debugf("Calling .Create()")
	// Create SSH Key and Pair
	publicKey, err := d.createKeyPair()
	if err != nil {
		return fmt.Errorf("unable to create key pair: %s", err)
	}
	d.Application.SSHUserKey = publicKey

	appYaml, err := applicationYaml(d)
	if err != nil {
		return err
	}

	taskSummary, err := application.CreateFromBytes(d.BrooklynClient, appYaml)
	d.ApplicationID = taskSummary.EntityId

	if err != nil {
		log.Error(err)
		return err
	}

	log.Infof("Task ID: %s and Entity ID: %s", taskSummary.Id, taskSummary.EntityId)

	// Wait for Instance Starting
	startingErr := d.waitForStarting()
	if startingErr != nil {
		log.Error(startingErr)
		return startingErr
	}

	// Wait for Instance to Running.
	runningErr := d.waitForInstance()
	if runningErr != nil {
		log.Error(runningErr)
		return runningErr
	}

	nodeID, err := GetNodeID(d.BrooklynClient, d.ApplicationID)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof(nodeID)
	d.NodeID = nodeID

	// Set SSHHostAddress Details
	err = d.sshHostAddress()
	if err != nil {
		log.Error(err)
		return err
	}

	// Set SSHHostSubnetAddress Details
	err = d.sshHostSubnetAddress()
	if err != nil {
		log.Error(err)
		return err
	}

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	log.Debugf("Calling .DriverName()")
	return driverName
}

// GetCreateFlags returns the mcnflag.Flag slice representing the flags
// that can be set, their descriptions and defaults.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	log.Debugf("Calling .GetCreateFlags()")
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   brooklynBaseURL,
			Usage:  "Brooklyn Base URL",
			Value:  defaultBrooklynBaseURL,
			EnvVar: "BROOKLYN_BASE_URL",
		},
		mcnflag.StringFlag{
			Name:   brooklynUser,
			Usage:  "Brooklyn User",
			EnvVar: "BROOKLYN_USER",
		},
		mcnflag.StringFlag{
			Name:   brooklynPassword,
			Usage:  "Brooklyn Password",
			EnvVar: "BROOKLYN_PASSWORD",
		},
		mcnflag.StringFlag{
			Name:   brooklynCatalogID,
			Usage:  "Brooklyn Catalog Id",
			Value:  defaultCatalogID,
			EnvVar: "BROOKLYN_CATALOG_ID",
		},
		mcnflag.StringFlag{
			Name:   brooklynTargetLocation,
			Usage:  "Brooklyn Target Location",
			EnvVar: "BROOKLYN_TARGET_LOCATION",
		},
		mcnflag.BoolFlag{
			Name:   brooklynSkipOS,
			Usage:  "Brooklyn Skip OS",
			EnvVar: "BROOKLYN_SKIP_OS",
		},
		mcnflag.StringFlag{
			Name:   brooklynTargetOS,
			Usage:  "Brooklyn Target OS",
			Value:  defaultOperatingSystem,
			EnvVar: "BROOKLYN_TARGET_OS",
		},
		mcnflag.StringFlag{
			Name:   brooklynTemplateSize,
			Usage:  "Brooklyn Template Size",
			Value:  defaultTemplateSize,
			EnvVar: "BROOKLYN_TEMPLATE_SIZE",
		},
		mcnflag.StringFlag{
			Name:   brooklynOpenPorts,
			Usage:  "Brooklyn Open Ports",
			EnvVar: "BROOKLYN_OPEN_PORTS",
		},
		mcnflag.BoolFlag{
			Name:   brooklynUsePrivateIP,
			Usage:  "Brooklyn Use Private IP",
			EnvVar: "BROOKLYN_USE_PRIVATE_IP",
		},
		mcnflag.StringFlag{
			Name:   brooklynMonitoringTool,
			Usage:  "Brooklyn Monitoring Tool",
			Value:  defaultMonitoringTool,
			EnvVar: "BROOKLYN_MONITORING_TOOL",
		},
		mcnflag.StringFlag{
			Name:   brooklynLogManagementTool,
			Usage:  "Brooklyn Log Management Tool",
			Value:  defaultLogManagementTool,
			EnvVar: "BROOKLYN_LOG_MANAGEMENT_TOOL",
		},
		mcnflag.BoolFlag{
			Name:   brooklynCustomStorage,
			Usage:  "Brooklyn Custom Storage",
			EnvVar: "BROOKLYN_CUSTOM_STORAGE",
		},
		mcnflag.IntFlag{
			Name:   brooklynCustomStorageSize,
			Usage:  "Brooklyn Custom Storage Size",
			EnvVar: "BROOKLYN_CUSTOM_STORAGE_STORAGE",
		},
		mcnflag.StringFlag{
			Name:   brooklynRhelSubscriptionID,
			Usage:  "Brooklyn Rhel Subscription ID",
			EnvVar: "BROOKLYN_RHEL_SUBSCRIPTION_ID",
		},
		mcnflag.StringFlag{
			Name:   brooklynRhelSubscriptionPassword,
			Usage:  "Brooklyn Rhel Subscription Password",
			EnvVar: "BROOKLYN_RHEL_SUBSCRIPTION_PASSWORD",
		},
	}
}

// GetIP returns an IP or hostname that this host is available at
// e.g. 1.2.3.4 or docker-host-d60b70a14d3a.cloudapp.net
func (d *Driver) GetIP() (string, error) {
	log.Debugf("Calling .GetIP()")
	if d.UsePrivateIP {
		log.Info(d.SSHHostSubnetAddress)
		return d.SSHHostSubnetAddress, nil
	}
	log.Info(d.SSHHostAddress.HostAndPort.Host)
	return d.SSHHostAddress.GetSSHHostname()
}

// GetSSHHostname returns hostname for use with ssh
func (d *Driver) GetSSHHostname() (string, error) {
	log.Debugf("Calling .GetSSHHostname()")
	return d.GetIP()
}

// GetSSHPort returns port for use with ssh
func (d *Driver) GetSSHPort() (int, error) {
	log.Debugf("Calling .GetSSHPort()")

	if d.UsePrivateIP {
		return defaultSSHPort, nil
	}

	sshPort, err := d.SSHHostAddress.GetSSHPort()
	log.Info(sshPort)
	return sshPort, err
}

// GetSSHUsername returns username for use with ssh
func (d *Driver) GetSSHUsername() string {
	log.Debugf("Calling .GetSSHUsername()")
	/*
		if d.SshHostAddress.User != "" {
			return d.SshHostAddress.User
		}
	*/
	return defaultSSHUser
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	log.Debugf("Calling .GetURL()")
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	sensorInfo, err := DescendantsSensor(d.BrooklynClient, d.ApplicationID, MappedPortSensorName)
	if err != nil {
		for key := range sensorInfo {
			dockerPort = sensorInfo[key]
			break
		}
	}

	url := fmt.Sprintf("tcp://%s:%d", ip, dockerPort)
	return url, nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	log.Debugf("Calling .GetState()")

	if d.ApplicationID == "" {
		log.Warnf("Application id is nil.")
		return state.Stopped, nil
	}

	nodeServiceState, err := GetNodeState(d.BrooklynClient, d.ApplicationID, d.NodeID)
	if err != nil {
		log.Warnf("Application node does not exists.")
		return state.Stopped, nil
	}

	log.Info(nodeServiceState)
	switch nodeServiceState {
	case "RUNNING":
		return state.Running, nil
	case "STARTING":
		return state.Starting, nil
	case "STOPPING":
		return state.Stopping, nil
	case "ERROR":
		return state.Error, nil
	case "STOPPED":
		return state.Stopped, nil
	default:
		return state.None, nil
	}
}

// GetApplicationState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetApplicationState() (state.State, error) {
	log.Debugf("Calling .GetApplicationState()")

	if d.ApplicationID == "" {
		log.Warnf("Application id is nil.")
		return state.Stopped, nil
	}

	applicationSummary, err := application.Application(d.BrooklynClient, d.ApplicationID)
	if err != nil {
		log.Warnf("Application does not exists.")
		return state.Stopped, nil
	}

	log.Info(applicationSummary.Status)
	switch applicationSummary.Status {
	case "RUNNING":
		return state.Running, nil
	case "STARTING":
		return state.Starting, nil
	case "STOPPING":
		return state.Stopping, nil
	case "ERROR":
		return state.Error, nil
	case "STOPPED":
		return state.Stopped, nil
	default:
		return state.None, nil
	}
}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	log.Debugf("Calling .Kill()")
	if d.ApplicationID == "" {
		log.Warnf("ApplicationId is not set.")
		return nil
	}

	_, err := application.Application(d.BrooklynClient, d.ApplicationID)

	if err != nil {
		log.Warnf("Application having id [%s] does not exists", d.ApplicationID)
		return nil
	}

	_, err = Delete(d.BrooklynClient, d.ApplicationID)
	if err != nil {
		log.Warnf("Error while killing application [%s]", d.ApplicationID)
		return nil
	}
	return nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	log.Debugf("Calling .PreCreateCheck()")
	// Validate specified server exists and reachable.
	state, err := server.Healthy(d.BrooklynClient)
	if err != nil {
		return err
	} else if state != "true" {
		return errors.New("Brooklyn Server is not healthy")
	}

	// Validate specified location exists.
	if _, err = LocationExists(d.BrooklynClient, d.Application.Location); err != nil {
		return err
	}

	// Validate specified catalog exists.
	if strings.Contains(d.Application.Type, ":") {
		tokens := strings.SplitN(d.Application.Type, ":", 2)
		catalog, err := CatalogByName(d.BrooklynClient, tokens[0], tokens[1])

		if err != nil {
			return err
		} else if strings.Contains(catalog.Id, d.Application.Type) {
			d.Application.Type = catalog.Id
		} else {
			return errorCatalogNotExists
		}
	} else {
		catalogs, err := CatalogByRegex(d.BrooklynClient, d.Application.Type)
		if err != nil {
			return err
		} else if len(catalogs) <= 0 {
			return errorCatalogNotExists
		}

		// Match for exact catalog.
		if len(catalogs) > 0 {
			for _, catalog := range catalogs {
				if catalog.Type == d.Application.Type {
					d.Application.Type = catalog.Id
					return nil
				}
			}
			return errorCatalogNotExists
		}
	}

	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	log.Debugf("Calling .Remove()")
	if d.ApplicationID == "" {
		// TODO Add code to remove application by searching application name
		log.Warnf("ApplicationId is not set, please verify does application exists.")
		return nil
	}
	_, err := Delete(d.BrooklynClient, d.ApplicationID)

	if err != nil {
		log.Warnf("Error while removing application [%s]", d.ApplicationID)
		return nil
	}
	return nil
}

// Restart a host. This may just call Stop(); Start() if the provider does not
// have any special restart behaviour.
func (d *Driver) Restart() error {
	log.Debugf("Calling .Restart()")
	err := TriggerRestart(d.BrooklynClient, d.ApplicationID, d.NodeID)
	return err
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(opts drivers.DriverOptions) error {
	log.Debugf("Calling .SetConfigFromFlags()")
	d.SetSwarmConfigFromFlags(opts)
	baseURL := opts.String(brooklynBaseURL)
	user := opts.String(brooklynUser)                     // mandatory
	password := opts.String(brooklynPassword)             // mandatory
	targetLocation := opts.String(brooklynTargetLocation) // mandatory
	skipOS := opts.Bool(brooklynSkipOS)
	catalogID := opts.String(brooklynCatalogID)
	targetOS := opts.String(brooklynTargetOS)
	templateSize := opts.String(brooklynTemplateSize)
	strOpenPorts := opts.String(brooklynOpenPorts)
	usePrivateIP := opts.Bool(brooklynUsePrivateIP)
	monitoringTool := opts.String(brooklynMonitoringTool)
	logManagementTool := opts.String(brooklynLogManagementTool)
	customStorageSize := opts.Int(brooklynCustomStorageSize)
	rhelSubscriptionID := strings.TrimSpace(opts.String(brooklynRhelSubscriptionID))
	rhelSubscriptionPassword := strings.TrimSpace(opts.String(brooklynRhelSubscriptionPassword))

	if user == "" {
		return errorMissingUser
	}

	if password == "" {
		return errorMissingPassword
	}

	if targetLocation == "" {
		return errorMissingLocation
	}

	if !contains(templateSize, templateSizes) {
		return errorInvalidTemplateSize
	}

	if !contains(monitoringTool, monitoringTools) {
		return errorInvalidMonitoringTool
	}

	if !contains(logManagementTool, logManagementTools) {
		return errorInvalidLogManagementTool
	}

	if strOpenPorts != "" && strings.Trim(strOpenPorts, " ") != "" {
		tokens := strings.Split(strOpenPorts, ",")
		var trimToken string
		for _, token := range tokens {
			trimToken = strings.Trim(token, " ")
			if !openPortsRegx.MatchString(trimToken) {
				log.Warnf("Invalid Token: ", trimToken)
				return errorInvalidOpenPorts
			}
		}
	}

	if !osRegx.MatchString(targetOS) {
		log.Warnf("Invalid operating system format: ", targetOS)
		return errorInvalidOS
	}

	if customStorageSize < 0 && customStorageSize == -1 {
		return errorInvalidCustomStorageSize
	}

	tokens := strings.Split(targetOS, ":")
	if len(tokens) != 2 {
		return errorInvalidOS
	}

	d.Application = NewApplication()
	d.Application.Name = d.MachineName
	d.Application.Location = targetLocation
	d.Application.Type = catalogID
	d.Application.Skip = skipOS
	d.Application.OsName = tokens[0]
	d.Application.OsVersion = tokens[1]
	d.Application.TemplateSize = templateSize
	d.Application.OpenPorts = strings.Split(strOpenPorts, ",")
	if monitoringTool == NewRelic {
		d.Application.NewRelic = true
	} else if monitoringTool == Dynatrace {
		d.Application.Dynatrace = true
	}
	if logManagementTool == LogEntries {
		d.Application.LogEntries = true
	}
	if customStorageSize > 0 {
		d.Application.CustomStorage = true
		d.Application.CustomStorageSize = customStorageSize
	}
	d.Application.RhelSubscriptionID = rhelSubscriptionID
	d.Application.RhelSubscriptionPassword = rhelSubscriptionPassword
	d.UsePrivateIP = usePrivateIP
	d.BrooklynClient = net.NewNetwork(baseURL, user, password, false)
	return nil
}

// Start a host
func (d *Driver) Start() error {
	log.Debugf("Calling .Start()")
	err := TriggerStart(d.BrooklynClient, d.ApplicationID, d.NodeID)
	return err
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	log.Debugf("Calling .Stop()")
	err := TriggerStop(d.BrooklynClient, d.ApplicationID, d.NodeID)
	return err
}

func (d *Driver) createKeyPair() (string, error) {
	log.Debugf("Calling .createKeyPair()")
	keyPath := ""

	log.Debugf("Creating New SSH Key")
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return "", err
	}
	keyPath = d.GetSSHKeyPath()

	_, err := ioutil.ReadFile(keyPath + ".pub")
	if err != nil {
		return "", err
	}

	log.Debugf(keyPath)
	//keyName := d.MachineName

	publicKey, err := ioutil.ReadFile(keyPath + ".pub")
	if err != nil {
		return "", err
	}

	return string(publicKey), nil
}

func (d *Driver) waitForInstance() error {
	log.Debugf("Calling .waitForInstance()")
	if err := mcnutils.WaitForSpecific(d.isInstanceRunning, 200, 3*time.Second); err != nil {
		return err
	}
	return nil
}

func (d *Driver) waitForStarting() error {
	log.Debugf("Calling .waitForStarting()")
	if err := mcnutils.WaitForSpecific(d.isInstanceStarting, 10, 3*time.Second); err != nil {
		return errorNotStarting
	}
	return nil
}

func (d *Driver) isInstanceRunning() bool {
	log.Debugf("Calling .isInstanceRunning()")
	st, err := d.GetApplicationState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Running {
		return true
	}
	return false
}

func (d *Driver) isInstanceStarting() bool {
	log.Debugf("Calling .isInstanceStarting()")
	st, err := d.GetApplicationState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Starting {
		return true
	}
	return false
}

func (d *Driver) isSwarmMaster() bool {
	log.Debugf("Calling .isSwarmMaster()")
	return d.SwarmMaster
}

func (d *Driver) sshHostAddress() error {
	log.Debugf("Calling .sshHostAddress()")
	sshHostAddress, err := DescendantsSSHHostAndPortSensor(d.BrooklynClient, d.ApplicationID)
	if err != nil {
		return err
	}
	d.SSHHostAddress = sshHostAddress
	return nil
}

func (d *Driver) sshHostSubnetAddress() error {
	log.Debugf("Calling .sshHostSubnetAddress()")
	sshHostSubnetAddress, err := DescendantsSSHHostSubnetAddress(d.BrooklynClient, d.ApplicationID)
	if err != nil {
		return err
	}
	d.SSHHostSubnetAddress = sshHostSubnetAddress
	return nil
}
