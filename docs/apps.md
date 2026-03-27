## Application Integration
### Asynchronous Mode Nginx\* with QAT
NGINX\* with asynchronous mode for Intel&reg; OpenSSL QAT Engine provides
significant performance improvement with QAT acceleration.
The asynchronous fork of NGINX\* can be found at the following Github\*
repository:

* [Intel&reg; QuickAssist Technology (QAT) Async Mode NGINX\*](https://github.com/intel/asynch_mode_nginx)

Follow the below link on how to enable Async mode Nginx\* with QAT Hardware and software
Acceleration using best known configuration.
[Async mode for Nginx\*](https://intel.github.io/quickassist/qatlib/asynch_nginx.html)

### HAProxy\* with QAT
HAProxy\* is a free, very fast and reliable reverse-proxy offering high availability,
load balancing, and proxying for TCP and HTTP-based applications.

Follow the instructions from the HAProxy [INSTALL](https://github.com/haproxy/haproxy/blob/master/INSTALL) file
to build and install HAProxy. The validated release is listed in [Software Requirements](software_requirements.md#applications). Use `USE_PTHREAD_EMULATION=1` option in the make command which improves performance
utilizing HAProxy's much lighter locks replacing OpensSL\* Pthread locks.

Add the following options along with other standard settings in the
HAProxy\* [Configuration File](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest)
to utilize QAT Acceleration.

#### QAT Engine Configuration
```bash
ssl-engine qatengine algo ALL
ssl-mode-async
```

#### QAT Provider Configuration
```bash
ssl-provider qatprovider
ssl-mode-async
```

## Case Studies
* [Intel® QuickAssist Technology - NGINX\* Performance White Paper](https://networkbuilders.intel.com/solutionslibrary/intel-quickassist-technology-nginx-performance-white-paper)
* [Accelerate HAProxy\* with Intel QAT](https://builders.intel.com/solutionslibrary/accelerating-haproxy-with-intel-quickassist-technology)

Other Application Integration and more case studies can be found at QAT link below
* [Intel® QuickAssist Technology (Intel® QAT)](https://www.intel.com/content/www/us/en/developer/topic-technology/open/quick-assist-technology/overview.html)
