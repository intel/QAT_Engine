# Troubleshooting

The most likely failure point is that the QAT Provider or QAT Engine is not
loading successfully. If this occurs, check the following:

* Enable debug logging with `--enable-qat_debug` when investigating issues. The
debug messages are logged to the console (for example, by `openssl speed`) or to
a file, depending on the application (for example, NGINX logs to
`path_to_nginx_install/logs/error.log`). To write the messages to a specific
file, use `--with-qat_debug_file=/opt/engine.log`.
* When using the QAT_HW OOT driver package, has the correct driver configuration
file been updated using `./update_config.sh`? Check that it has a `[SHIM]`
section and that the Intel&reg; QAT devices are up using `adf_ctl status`.
Otherwise, the following error is reported during the test. If co-existence is
enabled, the operation can use QAT_SW instead.
```bash
ADF_UIO_PROXY err: icp_adf_userProcessToStart: Error reading /dev/qat_dev_processes file
QAT HW initialization Failed.
```
* When using the QAT_HW OOT driver, is the driver configuration file
(`/etc/<qatdev_id>/conf`) configured with enough processes in the
`NumProcesses = <n>` setting, where `n` is the number of processes the
application uses? Otherwise, the following error is reported when a process
cannot obtain a QAT_HW instance. If QAT_SW is enabled, the process uses QAT_SW
as a fallback.
```bash
icp sal userstart fail:qat_hw_init.c
```
* When using the QATlib intree driver, see the
[installation guide](https://github.com/intel/qatlib/blob/main/INSTALL) for the
policy settings used to configure the number of processes and services required
for the workload.
* Is the Intel&reg; QAT driver running for QAT_HW? Run `adf_ctl status` and verify
that each required device reports `state: up`. Also verify that the Intel&reg; QAT
driver software has started.
* Were the paths configured correctly so that QAT Engine (`qatengine.so`) and
QAT Provider (`qatprovider.so`) were copied to the correct locations? Verify
that both files are present.
* Has the environment variable `OPENSSL_ENGINES` been correctly defined and
exported to the shell? Verify that it points to the directory containing
`qatengine.so`.
* For the QAT Provider, has the environment variable `OPENSSL_MODULES` been
correctly defined and exported to point to the directory containing
`qatprovider.so`? The default location is `<openssl-install>/lib64/ossl-modules/`.
If not set, OpenSSL\* will only search the compiled-in default modules path.
* When using QAT Provider (`qatprovider`), ensure the OpenSSL\* `default` provider
is also explicitly activated, either with `-provider default` on the command line or
`activate = 1` under `[default_sect]` in `openssl.cnf`. Without it, algorithms
not handled by QAT Provider (for example, certificate parsing and internal digest
operations) will fail with `unknown algorithm` or `no provider` errors.
* When building against a prebuilt OpenSSL RPM package, are the OpenSSL
development packages installed? Install `openssl-devel` on Red Hat\*-based
distributions or `libssl-dev` on Debian\*-based distributions.
* For QAT_SW acceleration, verify that the dependent libraries are installed in
their default paths. For non-default paths, use
`--with-qat_sw_crypto_mb_install_dir` for crypto_mb and
`--with-qat_sw_ipsec_mb_install_dir` for ipsec_mb.
* On certain systems, `qatengine.so` or `qatprovider.so` might not be able to
locate `libcrypto.so` and `libssl.so` if built from OpenSSL\* source. Add the
OpenSSL\* installation directory to `LD_LIBRARY_PATH`, as shown below:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/ssl/lib64
```
* If USDM memory allocation fails for a root or non-root user, check the locked
memory limit with `ulimit -l`. Increase the limit if it is too low.
* DH, DSA, SHA-1, RSA keys smaller than 2048 bits, and EC curves smaller than
256 bits are considered insecure and are disabled by default in the QAT driver
and QAT Engine. To use these algorithms, rebuild the QAT driver with
`--enable-legacy-algorithms` and QAT Engine with the
`--enable-qat_insecure_algorithms` configure option.
* **System-wide `openssl.cnf` changes affect all OpenSSL applications, including OpenSSH.**
When QAT Provider (`qatprovider`) or QAT Engine (`qatengine`) is activated in the
system `openssl.cnf`, every OpenSSL-based application on the host, including `sshd` and `ssh`, will load and
use QAT for its crypto operations. QAT hardware has a finite number of crypto instances;
SSH sessions consuming those instances can leave your target application (for example, NGINX or
HAProxy) with fewer available instances, causing performance degradation or
`QAT HW initialization Failed` errors that appear unrelated to SSH activity.

  To avoid this, prefer scoping the configuration to your application rather than
  modifying the system-wide `openssl.cnf`:
  ```bash
  # Set per-application via environment variable instead of system openssl.cnf
  export OPENSSL_CONF=/path/to/your/app-specific/openssl.cnf
  ```

## QAT Provider Application Integration

The following symptoms apply to applications that drive `qatprovider` directly,
as described in [Application Integration](qat_provider.md#application-integration).

| Symptom | Likely cause |
| :--- | :--- |
| Everything works, no errors, but no performance gain and no QAT activity | External or heuristic polling is selected but the application never registered as the poller. Write `QAT_PROV_PARAM_INIT_PROVIDER` at start-up. See [External polling](qat_provider.md#external-polling). |
| Asymmetric operations are offloaded, symmetric are not | The default property query is not set, so AES-GCM/CCM, SM4 and CHACHA20-POLY1305 resolve to the default provider. Call `EVP_set_default_properties(NULL, QAT_PROV_DEFAULT_PROPERTY_QUERY)`. |
| `OSSL_PROVIDER_load()` returns `NULL` | Check for an invalid `qat_poll_mode` value in `openssl.cnf`. Also check that `qatprovider.so` is in the OpenSSL\* modules directory or that `OPENSSL_MODULES` is set. |
| A pushed polling mode has no effect | The mode was already committed, either by `openssl.cnf` or by an earlier cryptographic operation. Read `QAT_PROV_PARAM_CONFIGURED_FROM_CNF` and push configuration before `QAT_PROV_PARAM_INIT_PROVIDER`. |
| Writing `0` to a polling parameter does not disable it | By design: only non-zero values are applied. Polling mode cannot be turned off at runtime; restart the process. |
| `QAT_PROV_PARAM_POLL` always returns `QAT_PROV_POLL_NOT_READY` | The provider is not initialised, or external polling is not enabled. Verify both by reading the effective values back. |
| Requests complete only when new connections arrive | No backstop timer. Add a periodic poll in addition to the event-loop poll. |
| Requests are abandoned at shutdown or reload | The poll timer was cancelled before the drain completed. Keep it alive for the whole drain window. |
| `qat_engine_init` or `icp_sal_userStart` fails with no devices found | A driver or platform level problem rather than an integration one. See the driver checks above and [Installation Instructions](install.md). |
| A setting appears to be ignored entirely | A misspelled parameter name may not be reported as an error. Define names once in your application rather than repeating string literals at each call site. |
