# Using the OpenSSL\* Configuration File to Load/Initialize Providers

OpenSSL\* 3.x introduced a provider model as the successor to the engine
interface. The Intel&reg; QAT Provider (`qatprovider`) can be loaded via the
`openssl.cnf` file in the same way as engines, using the `providers`
configuration module instead of `engines`. The same application initialization
requirement applies: `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)` must
be called before any OpenSSL\* library call, as described in the engine section
below.

Add the following snippet to your `openssl.cnf` to load the Intel&reg; QAT
Provider. The `openssl_conf` line belongs in the global section (before the
first bracketed section header); the remaining sections can be appended
anywhere below it:

    openssl_conf = openssl_init

    [ openssl_init ]
    providers = provider_section

    [ provider_section ]
    qatprovider = qat_prov_section
    default = default_sect

    [ qat_prov_section ]
    module = /usr/local/lib64/ossl-modules/qatprovider.so
    activate = 1

    [ default_sect ]
    activate = 1

### Explanation of the Provider configuration

* `openssl_conf = openssl_init` — points OpenSSL\* at the initialization
  section. `openssl_init` is the default name; a different name may be used if
  preferred.
* `[ openssl_init ]` with `providers = provider_section` — registers the
  `providers` configuration module and names the section that lists the
  providers to be loaded.
* `[ provider_section ]` — lists the providers to activate. Both `qatprovider`
  and the built-in `default` provider are listed so that algorithms not
  offloaded by QAT remain available via software.
* `[ qat_prov_section ]` — settings for the Intel&reg; QAT Provider:
  * `module` is the path to the loadable shared library implementing the
    provider. This line can be omitted if the provider module is located
    within the standard OpenSSL\* modules directory (typically
    `<openssl-install>/lib64/ossl-modules/`).
  * `activate = 1` instructs OpenSSL\* to load and initialise the provider.
* `[ default_sect ]` with `activate = 1` — activates the default provider to
  ensure software fallback for any algorithms not handled by the QAT
  Provider.

For further details on using the OpenSSL\* configuration file please see the
OpenSSL\* online documentation located at:
<https://www.openssl.org/docs/man3.0/man5/config.html>

# Using the OpenSSL\* Configuration File to Load/Initialize Engines

OpenSSL\* includes support for loading and initializing engines via the
openssl.cnf file. The openssl.cnf file is contained in the `ssl` subdirectory of
the path you install OpenSSL\* to.  By default OpenSSL\* does not load the
openssl.cnf file at initialization time. In order to load the file you need to
make the following function call from your application as the first call to the
OpenSSL\* library:

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

Add the following snippet to your `openssl.cnf` to load the Intel&reg; QAT
OpenSSL\* Engine. The `openssl_conf` line belongs in the global section (before
the first bracketed section header); the remaining sections can be appended
anywhere below it:

    openssl_conf = openssl_init

    [ openssl_init ]
    engines = engine_section

    [ engine_section ]
    qat = qat_section

    [ qat_section ]
    engine_id = qatengine
    dynamic_path = /usr/local/ssl/lib/engines-3/qatengine.so
    # Add engine specific messages here
    default_algorithms = ALL

### Explanation of the Engine configuration

* `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)` — the second parameter
  determines the name of the section containing the application specific
  initialization settings. `NULL` defaults to `openssl_conf`. To use a
  different section, declare an `OPENSSL_INIT_SETTINGS` structure and set the
  `appname` field to the desired section name. The snippet above assumes the
  default `openssl_conf` section name.

  If converting an existing application that uses the now deprecated call
  `OPENSSL_config(NULL)`, the behaviour is currently equivalent, but as it is
  deprecated it should not be relied upon for future use.

  See <https://www.openssl.org/docs/man3.0/man3/OPENSSL_init_crypto.html> for
  further details.

* `openssl_conf = openssl_init` — placed in the global section, points
  OpenSSL\* at the initialization section. A name other than `openssl_init`
  may be used if preferred. The `openssl_init` section itself may appear as
  the first bracketed section or further down the configuration file.
* `[ openssl_init ]` with `engines = engine_section` — registers the `engines`
  configuration module and names the section that lists the engines to be
  loaded.
* `[ engine_section ]` with `qat = qat_section` — lists the engines to load
  and points at the per-engine settings section.
* `[ qat_section ]` — settings for the Intel&reg; QAT OpenSSL\* Engine:
  * `engine_id` specifies the name of the engine to load (should be
    `qatengine`).
  * `dynamic_path` is the location of the loadable shared library
    implementing the engine. This line can be omitted if the engine is
    located within the standard path that OpenSSL\* was installed to.
  * `default_algorithms` specifies which algorithms supplied by the engine
    should be used by default. Specify `ALL` to make all algorithms supplied
    by the engine be used by default.

#### Engine specific messages

In addition the `qat_section` may contain settings that call custom engine
specific messages. For instance:

    ENABLE_EVENT_DRIVEN_MODE = EMPTY

is functionally equivalent of making the following engine specific message
function call:

    ENGINE_ctrl_cmd(e, "ENABLE_EVENT_DRIVEN_MODE", 0, NULL, NULL, 0);

Set the value to `EMPTY` if there are no parameters to pass, or assign the
value that would be passed as the 4th parameter of the equivalent
`ENGINE_ctrl_cmd` call. This mechanism is only useful for passing simple
values at engine initialization time. You cannot pass 3rd parameter values,
pass complex structures or deal with return values via this mechanism.

Engine specific messages should be specified before the `default_algorithms`
setting or incorrect behaviour may result. The following [messages](engine_specific_messages.md) are supported:

* `ENABLE_EVENT_DRIVEN_POLLING_MODE`
* `ENABLE_EXTERNAL_POLLING`
* `ENABLE_INLINE_POLLING`
* `ENABLE_SW_FALLBACK`
* `SET_INTERNAL_POLL_INTERVAL`
* `SET_EPOLL_TIMEOUT`
* `SET_MAX_RETRY_COUNT`

In case of forking, the custom values are inherited by the child process.

By default the engine will get initialized at the end of this section (after all
the custom engine specific messages have been sent). This can be controlled via
an additional `init` setting that is out of scope of the documentation here.

For further details on using the OpenSSL\* configuration file please see the
OpenSSL\* online documentation located at:
<https://www.openssl.org/docs/man3.0/man5/config.html>

## TLS Application Integration

Once `openssl.cnf` is configured to load either the Intel&reg; QAT Engine or
the Intel&reg; QAT Provider as described above, TLS applications such as async
mode NGINX\*, HAProxy\*, and the OpenSSL\* speed utility will automatically
benefit from QAT acceleration without requiring explicit `-engine qatengine` or
`-provider qatprovider` flags on the command line or in application-specific
configuration.
