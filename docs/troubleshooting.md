# Troubleshooting

The most likely failure point is that the Intel&reg; QAT OpenSSL\* Engine is not
loading successfully. If this occurs some of the things to check are:

* Enabling debug settings with QAT_Engine is valuable tool when debugging issues
with QAT_Engine using `--enable-qat_debug`. The debug messages would be logged in
the console(Eg: OpenSSL Speed) or to a file depending on the application(Eg: Nginx
would be on `path_to_nginx_install/logs/error.log`). If you prefer to write to a
file use Eg:`--with-qat_debug_file=/opt/engine.log`.
* When using qat_hw OOT driver package,  Has the correct driver config file
from `qat_hw_config` been copied to `/etc`? Check it has a `[SHIM]` section and
that the Intel&reg; QAT Driver was restarted so that it picked up the new
config file. Otherwise below error would be reported during the test.
```bash
ADF_UIO_PROXY err: icp_adf_userProcessToStart: Error reading /dev/qat_dev_processes file
QAT HW initialization Failed.
```
* In case of qat_hw OOT driver, has the driver config file(`/etc/qatdev_id/conf`)
is configured with enough number of process in the setting `NumProcesses = <n>`
where n is the number of process your application would be using.  Otherwise
the below error would be reported for the process that is not getting qat_hw
instance. If QAT_SW is enabled, the process would be using qat_sw as a fallback
mechanism.
```bash
icp sal userstart fail:qat_hw_init.c
```
* In case of qat_hw qatlib intree driver, refer [install](https://github.com/intel/qatlib/blob/main/INSTALL)
page for the policy settings to configure the Numprocess and service required as
per the use case for better performance.
* Is the Intel&reg; QAT Driver up and running for qat_hw?  Check by running `adf_ctl`,
device details along with the state should be `state: up`. Also check the
Intel&reg; QAT Driver software has been started.
* Were the paths set correctly so that the `qatengine.so` for engine and `qatprovider.so`
for provider was copied to the correct location? Check they really are there.
* Has the environment variable `OPENSSL_ENGINES` been correctly defined and
exported to the shell? Also check it is really pointing to the correct location.
* If building from OpenSSL prebuilt RPM Package, has the OpenSSL development
packages (openssl-devel for Redhat\* based distribution and libssl-devel
for Debian\* based distribution) been installed ?
* In case of qat_sw acceleration, has the dependent libraries are installed in
the default path or provide the path via `--with-qat_sw_crypto_mb_install_dir`
(for crypto_mb) and `--with-qat_sw_ipsec_mb_install_dir` (for ipsec_mb) if
installed in the path other than default.
* On certain systems, it might be possible that `qatengine.so` or `qatprovider.so`
is not able to locate `libcrypto.so` & `libssl.so` if built from OpenSSL\* source.
It is recommended to add the OpenSSL\* install dir to LD_LIBRARY_PATH as per th
example below
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/ssl/lib64
```
* If seeing failures with USDM memory allocation, either with non-root or root user
check memlock limit with `ulimit -l` and increase the memlock limit to
desired value if it is low.
* Algorithms like DH, DSA, SHA1, RSA keysizes < 2048, EC curves < 256 bits are
considered insecure and disabled by default at QAT_HW driver and QAT Engine.
If you prefer to use these algorithms, Rebuild QAT_HW using `--enable-legacy-algorithms`
and QAT Engine using `--enable-qat_insecure_algorithms` configure option.
