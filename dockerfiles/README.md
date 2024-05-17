# Intel QuickAssist Technology QAT Engine Docker README

This document covers the usage of the Intel® QuickAssist Technology Software in Linux* containers.
It explains about the environment setup to run QAT Engine test on the docker container, docker build and docker run commands.

#### Platform Supported

It supports all the platform that is supported by QATLIB.(i.e.,SPR,EMR)

#### Pre-requisites

Refer https://intel.github.io/quickassist/AppNotes/Containers/setup.html#updating-the-bios-settings

Note: The host shouldn't have qatlib installed and don't run qat service.

# Steps to be followed in order to set the desired services in the devices

```
## Bring down the QAT devices
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo down > /sys/bus/pci/devices/$i/qat/state;done

## Set up the services to crypto alone
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo “sym;asym “ > /sys/bus/pci/devices/$i/qat/cfg_services;done

## Bring up the QAT devices
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo up> /sys/bus/pci/devices/$i/qat/state;done

## Check the status of the QAT devices
    for i in `lspci -D -d :4940| awk '{print $1}'`; do cat /sys/bus/pci/devices/$i/qat/state;done

## Enable VF for the PF in the host
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo 16|sudo tee /sys/bus/pci/devices/$i/sriov_numvfs; done

## Add QAT group and Permission to the VF devices in the host
    chown root.qat /dev/vfio/*
    chmod 660 /dev/vfio/*
```

#### Two separate Dockerfile file structure:

1. QAT Crypto base dockerfile 
   -  docker/qat_crypto_base/Dockerfile
2. HAproxy + Crypto base dockerfile 
   - docker/haproxy/Dockerfile

#### Docker Command

# Command to build docker image

```
docker build --build-arg GID=$(getent group qat | cut -d ':' -f 3) -t <docker_image_name> <path-to-dockerfile> --no-cache
```
Note: GID is the group id of qat group in the host.

# Command for Container creation and execution

### Test using OpenSSL\* speed utility

```
docker run -it --cap-add=IPC_LOCK --security-opt seccomp=unconfined --security-opt apparmor=unconfined $(for i in `ls /dev/vfio/*`; do echo --device $i; done)  --cpuset-cpus  <2-n+1> --env QAT_POLICY=1 --ulimit memlock=524288000:524288000 < docker_image_name> openssl speed -engine qatengine -elapsed -async_jobs 72  -multi <n> <algo>
```
### Test using HAproxy\* haproxy utility

```
Server command: docker run --rm -it  --cpuset-cpus <2-n+1> --cap-add=IPC_LOCK --security-opt seccomp=unconfined --security-opt apparmor=unconfined $(for i in `ls /dev/vfio/*`; do echo --device $i; done) --env QAT_POLICY=1 --ulimit memlock=524288000:524288000   -v /usr/local/etc/haproxy/:/usr/local/etc/haproxy/ -d -p 8080:8080 < docker_image_name> haproxy -f /usr/local/etc/haproxy/haproxy.cfg

Client command: openssl s_time -connect optical1:8080 -cipher AES128-SHA256 -www /20b-file.html -time 5
```

Note: n is number of process or thread

# The below link explains in detail about the parameters passed in the docker run command

    https://intel.github.io/quickassist/AppNotes/Containers/run.html

Note: 8080 port to be used for starting the haproxy service.HAproxy config file mounted from the host to the container using -v /usr/local/etc/haproxy/haproxy.cfg.

