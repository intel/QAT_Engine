# QAT Provider Container Support

This directory contains the following Dockerfiles, which can be built as container
images on platforms with an [Intel® QuickAssist 4xxx Series](https://www.intel.com/content/www/us/en/products/details/processors/xeon/scalable.html)
QAT device.

* [QAT crypto base](#qat-crypto-base)
* [HAproxy with QAT crypto base](#haproxy-with-qat-crypto-base)

## QAT crypto base
The `qat_crypto_base/Dockerfile` image uses QAT Provider (`qatprovider`) and is built with the
OpenSSL, QAT_HW (QATlib intree driver), and QAT_SW versions listed in
[Software Requirements](../docs/software_requirements.md). The image enables
QAT_HW and QAT_SW co-existence and behaves as described in
[QAT_HW and QAT_SW Co-existence](../docs/qat_coex.md#qat_hw-and-qat_sw-co-existence).

## HAProxy with QAT crypto base
The `haproxy/Dockerfile` image uses HAProxy v3.4.0 and the QAT crypto base image
described above. Modify the sample `haproxy/haproxy.cfg` configuration for the
workload and mount it from the host with `-v /usr/local/etc/haproxy/haproxy.cfg`.

## Docker setup and testing

See the [QAT container setup guide](https://intel.github.io/quickassist/AppNotes/Containers/setup.html)
to prepare a QAT_HW (QATlib intree) host with a QAT 4xxx device. Stop the QAT
service if it is running on the host.

### QAT_HW settings
Follow the steps below to enable the required services. In step 2, enable only
the asymmetric service, only the symmetric service, or both, depending on the
workload. Configure only the required services for the best performance.

1. Bring down the QAT devices
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo down > /sys/bus/pci/devices/$i/qat/state;done
```

2. Set up the required crypto service(s)
```
    for i in `lspci -D -d :4940 | awk '{print $1}'`; do echo 'sym;asym' > /sys/bus/pci/devices/$i/qat/cfg_services; done
```

3. Bring up the QAT devices
```
    for i in `lspci -D -d :4940 | awk '{print $1}'`; do echo up > /sys/bus/pci/devices/$i/qat/state; done
```

4. Check the status of the QAT devices
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do cat /sys/bus/pci/devices/$i/qat/state;done
```

5. Enable VF for the PF in the host
```
    for i in `lspci -D -d :4940| awk '{print $1}'`; do echo 16|sudo tee /sys/bus/pci/devices/$i/sriov_numvfs; done
```

6. Grant the QAT group permission to access the VF devices on the host
```
    chown root:qat /dev/vfio/*
    chmod 660 /dev/vfio/*
```

### Image creation

Build a Docker image with the following command and an appropriate image name.

```
docker build --build-arg GID=$(getent group qat | cut -d ':' -f 3) -t <docker_image_name> <path-to-dockerfile> --no-cache
```
Note: `GID` is the group ID of the `qat` group on the host.

### Testing QAT Crypto base using OpenSSL\* speed utility

```
docker run -it --cap-add=IPC_LOCK --security-opt seccomp=unconfined --security-opt apparmor=unconfined $(for i in `ls /dev/vfio/*`; do echo --device $i; done)  --cpuset-cpus  <2-n+1> --env QAT_POLICY=1 --ulimit memlock=524288000:524288000 <docker_image_name> openssl speed -provider qatprovider -provider default -elapsed -async_jobs 72  -multi <n> <algo>
```

### Testing Haproxy

```
Server command: docker run --rm -it  --cpuset-cpus <2-n+1> --cap-add=IPC_LOCK --security-opt seccomp=unconfined --security-opt apparmor=unconfined $(for i in `ls /dev/vfio/*`; do echo --device $i; done) --env QAT_POLICY=1 --ulimit memlock=524288000:524288000 -v /usr/local/etc/haproxy/:/usr/local/etc/haproxy/ -d -p 8080:8080 <docker_image_name> haproxy -f /usr/local/etc/haproxy/haproxy.cfg

Client command: openssl s_time -connect <server_ip>:8080 -cipher AES128-SHA256 -www /20b-file.html -time 5
```

Note: `n` is the number of processes or threads. Port 8080 is used for the
HAProxy service. Mount the HAProxy configuration file from the host with
`-v /usr/local/etc/haproxy/haproxy.cfg`.
