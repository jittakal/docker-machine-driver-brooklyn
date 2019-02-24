Overview
========

Docker machine driver for Apache Brooklyn

Getting Started
===============

Installing GO
-------------

Follow the instructions mention in getting started on [Installing Go](https://golang.org/doc/)


Build The Driver
----------------
- go get ./...
- go build github.com/jittakal/docker-machine-driver-brooklyn
- go run github.com/jittakal/docker-machine-driver-brooklyn

Development Environment
-----------------------

Glide vendor tool setup

```
curl https://glide.sh/get | sh
```

```
glide install
```

To be replace with 

Dep vendor tool setup

```
curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
```

Build Latest Driver
```
$ go build ../src/github.com/jittakal/docker-machine-driver-brooklyn.go
```

Create DockerHost Without Swarm Manager
```
$ docker-machine create --driver brooklyn  \
    --brooklyn-base-url https://brooklyn-test \
    --brooklyn-user brooklyn-user \
    --brooklyn-password brooklyn-brooklyn-password --brooklyn-target-location "brooklyn-target-location" --brooklyn-target-os ubuntu:15.10 machinename
```

Create DockerHost Without Swarm Manager with T-shirt size option
```
$ docker-machine create --driver brooklyn  \
    --brooklyn-base-url https://brooklyn-test \
    --brooklyn-user brooklyn-user \
    --brooklyn-password brooklyn-password --brooklyn-target-location "brooklyn-target-location" --brooklyn-target-os ubuntu:15.10 --brooklyn-template-size large machinename
```
    
Create Docker Swarm Manager
```
$ docker-machine create --driver brooklyn  \
    --brooklyn-base-url https://brooklyn-test \
    --brooklyn-user brooklyn-user \
    --brooklyn-password brooklyn-password --brooklyn-target-location "brooklyn-target-location" \ 
    --swarm --swarm-master --swarm-discovery token://SWARM_CLUSTER_TOKEN \    
    swarm-manager
```

Create Docker Swarm Manager with T-shirt size option
```
$ docker-machine create --driver brooklyn  \
    --brooklyn-base-url https://brooklyn-test \
    --brooklyn-user brooklyn-user \
    --brooklyn-password brooklyn-password --brooklyn-target-location "brooklyn-target-location" --brooklyn-template-size large \ 
    --swarm --swarm-master --swarm-discovery token://SWARM_CLUSTER_TOKEN \    
    swarm-manager
```
    
Create Docker Host With Registering Swarm Manager
```
$ docker-machine create --driver brooklyn  \
    --brooklyn-base-url https://brooklyn-test \
    --brooklyn-user brooklyn-user \
    --brooklyn-password brooklyn-password --brooklyn-target-location "brooklyn-target-location" \ 
    --swarm --swarm-discovery token://SWARM_CLUSTER_TOKEN \    
    node-01
```
    

Test Newly created Dockerhost
```
$ docker --tlsverify --tlscacert=/home/user/.docker/machine/certs/ca.pem \ 
    --tlscert=/home/user/.docker/machine/certs/cert.pem \
    --tlskey=/home/user/.docker/machine/certs/key.pem \
    -H=ec2-host:2376 version
```
    
Docker Swarm Manager Info
```
$ docker --tlsverify --tlscacert=/home/user/.docker/machine/certs/ca.pem \
    --tlscert=/home/user/.docker/machine/certs/cert.pem \
    --tlskey=/home/user/.docker/machine/certs/key.pem \
    -H=ec2-host:3376 info
```
