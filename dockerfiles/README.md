# Intel® QuickAssist Technology(QAT) OpenSSL\* Engine Container support

Supports below Dockerfiles which can be built into docker images on the platforms
with [Intel® QuickAssist 4xxx Series](https://www.intel.com/content/www/us/en/products/details/processors/xeon/scalable.html)
QAT device.

* [QAT crypto base](#qat-crypto-base)
* [HAproxy with QAT crypto base](#haproxy-with-qat-crypto-base)

## QAT crypto base
This Dockerfile(qat_crypto_base/Dockerfile) with qatengine is built on top of latest OpenSSL, QAT_HW(qatlib intree driver)
and QAT_SW with software versions mentioned in [software_requirements](../docs/software_requirements.md) section.
This contains QAT_HW and QAT_SW co-existence build and works as defined in [co-existence section](../docs/qat_coex.md#qat_hw-and-qat_sw-co-existence)

## Haproxy with QAT crypto base
This Dockerfile(haproxy/Dockerfile) is built with Haproxy release version v2.8.0 along
with QAT crypto base mentioned above. Sample Haproxy configuration file is located at `haproxy/haproxy.cfg`
which can be modified as per the required use case and to be mounted from the host to the container using
`-v /usr/local/etc/haproxy/haproxy.cfg`.

## Docker setup and testing

Refer [here](https://intel.github.io/quickassist/AppNotes/Containers/setup.html)
for setting up the host for QAT_HW (qatlib intree) if the platform has QAT 4xxx Hardware
device. Stop QAT service if any running on the host.

### QAT_HW settings
Follow the below steps to enable required service. The service can be asym only, sym only or both
in step 2 depending on the particular use case. Configure the required service only to get best performance.

1. Bring down the QAT devices
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo down > /sys/bus/pci/devices/$i/qat/state;done
```

2. Set up the required crypto service(s)
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo “sym;asym “ > /sys/bus/pci/devices/$i/qat/cfg_services;done
```

3. Bring up the QAT devices
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo up> /sys/bus/pci/devices/$i/qat/state;done
```

4. Check the status of the QAT devices
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do cat /sys/bus/pci/devices/$i/qat/state;done
```

5. Enable VF for the PF in the host
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo 16|sudo tee /sys/bus/pci/devices/$i/sriov_numvfs; done
```

6. Add QAT group and Permission to the VF devices in the host
```
    chown root.qat /dev/vfio/*
    chmod 660 /dev/vfio/*
```

### Image creation

Docker images can be build using the below command with appropiate image name.

```
docker build --build-arg GID=$(getent group qat | cut -d ':' -f 3) -t <docker_image_name> <path-to-dockerfile> --no-cache
```
Note: GID is the group id of qat group in the host.

### Testing QAT Crypto base using OpenSSL\* speed utility

```
docker run -it --cap-add=IPC_LOCK --security-opt seccomp=unconfined --security-opt apparmor=unconfined $(for i in `ls /dev/vfio/*`; do echo --device $i; done)  --cpuset-cpus  <2-n+1> --env QAT_POLICY=1 --ulimit memlock=524288000:524288000 < docker_image_name> openssl speed -engine qatengine -elapsed -async_jobs 72  -multi <n> <algo>
```

### Testing Haproxy

```
Server command: docker run --rm -it  --cpuset-cpus <2-n+1> --cap-add=IPC_LOCK --security-opt seccomp=unconfined --security-opt apparmor=unconfined $(for i in `ls /dev/vfio/*`; do echo --device $i; done) --env QAT_POLICY=1 --ulimit memlock=524288000:524288000 -v /usr/local/etc/haproxy/:/usr/local/etc/haproxy/ -d -p 8080:8080 < docker_image_name> haproxy -f /usr/local/etc/haproxy/haproxy.cfg

Client command: openssl s_time -connect <server_ip>:8080 -cipher AES128-SHA256 -www /20b-file.html -time 5
```

Note: n is number of process or thread. 8080 port to be used for starting the haproxy service. HAproxy config file mounted from the host to the container using -v /usr/local/etc/haproxy/haproxy.cfg.
