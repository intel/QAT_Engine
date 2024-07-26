## Application Integration
### Asynchronous Mode Nginx\* with QAT
NGINX\* with asynchronous mode for Intel&reg; OpenSSL QAT Engine provides
significant performance improvement with QAT acceleration.
The asynchronous fork of NGINX\* can be found at the following Github\*
repository:

* [Intel&reg; QuickAssist Technology (QAT) Async Mode NGINX\*](https://github.com/intel/asynch_mode_nginx)

Follow the below link on how to enable Async mode Nginx\* with QAT Hardware and software
Aceeleration using best known configuration.
[Async mode for Nginx\*](https://intel.github.io/quickassist/qatlib/asynch_nginx.html)

### NGINX\* QUIC with QAT
Experimental QUIC support for NGINX\* with Intel&reg; QAT Engine for
BoringSSL\* Library can be found [here](https://www.intel.com/content/www/us/en/content-details/737522/experimental-quic-support-for-nginx.html)

### HAProxy\* with QAT
HAProxy\* is a free, very fast and reliable reverse-proxy offering high availability,
load balancing, and proxying for TCP and HTTP-based applications.

Follow the instructions from HAProxy [Install](https://github.com/haproxy/haproxy/blob/master/INSTALL)
to build and install Haproxy. Use `USE_PTHREAD_EMULATION=1` option in the make command which improves performance
utilizing HAProxy's much lighter locks replacing OpensSL\* Pthread locks.

Add the following options along with other standard settings in the
HAProxy\* [Configuration File](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest)
to utilize QAT Acceleration.

```bash
ssl-engine qatengine algo ALL
ssl-mode-async
```

## Case Studies
* [Intel&reg; QuickAssist Technology and OpenSSL-1.1.0:Performance](https://www.intel.com/content/www/us/en/content-details/709581/intel-quickassist-technology-and-openssl-1-1-0-performance.html)
* [Intel® QuickAssist Technology - NGINX\* Performance White Paper](https://networkbuilders.intel.com/solutionslibrary/intel-quickassist-technology-nginx-performance-white-paper)
* [Accelerate HAProxy\* with Intel QAT](https://www.intel.com/content/www/us/en/content-details/814574/accelerating-haproxy-with-intel-quickassist-technology.html)

Other Application Integration and more case studies can be found at QAT link below
* [Intel® QuickAssist Technology (Intel® QAT)](https://www.intel.com/content/www/us/en/developer/topic-technology/open/quick-assist-technology/overview.html)
