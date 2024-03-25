# Using the OpenSSL\* Configuration File to Load/Initialize Engines

OpenSSL\* includes support for loading and initializing engines via the
openssl.cnf file. The openssl.cnf file is contained in the `ssl` subdirectory of
the path you install OpenSSL\* to.  By default OpenSSL\* does not load the
openssl.cnf file at initialization time. In order to load the file you need to
make the following function call from your application as the first call to the
OpenSSL\* library:

    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

The second parameter determines the name of the section containing the
application specific initialization settings. If you set the parameter to NULL
as in the example above it will default to look for the `openssl_conf` section.
If you want to use your own section you should declare a structure of type
`OPENSSL_INIT_SETTINGS` and set the `appname` field to a string containing the
section name you wish to use. The example config file sections below assume you
are using the default `openssl_conf` section name.

If converting an existing application to use the Intel&reg; QAT OpenSSL\* Engine
you may find that the application instead makes the now deprecated call to:

    OPENSSL_config(NULL);

Where the parameter is a const char* pointer to the `appname` section you want
to use, or NULL to use the default `openssl_conf` section.

Currently this will give the same behaviour as the
`OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)` call but as it is
deprecated it should not be relied upon for future use.

For further details on using the OPENSSL_init_crypto function please see the
OpenSSL\* online documentation located at:
<https://www.openssl.org/docs/man1.1.0/crypto/OPENSSL_init_crypto.html>

In order to start using the openssl.cnf file it needs some additional lines
adding. You should add the following statement in the global section (this is
the section before the first bracketed section header):

    openssl_conf = openssl_init

The string `openssl_init` is the name of the section in the configuration file
which describes the application specific settings. You do not need to stick to
the naming convention here if you prefer to use a different name.

The `openssl_init` section can be located at the end of the global section (as
the first bracketed section), or further down the configuration file. It should
have the following added:

    [ openssl_init ]
    engines = engine_section

The `engines` string is a keyword that OpenSSL\* recognises as a configuration
module. It should be set to a string which is the section name containing a list
of the engines to be loaded. So for the Intel&reg; QAT OpenSSL\* Engine the
section should contain:

    [ engine_section ]
    qat = qat_section

The `qat_section` contains all the settings relating to that particular engine.
For instance it may contain:

    [ qat_section ]
    engine_id = qatengine
    dynamic_path = /usr/local/ssl/lib/engines-1.1/qatengine.so
    # Add engine specific messages here
    default_algorithms = ALL

Where `engine_id` specifies the name of engine to load (should be `qatengine`).

Where `dynamic_path` is the location of the loadable shared library implementing
the engine. There is no need to specify this line if the engine is located
within the standard path that OpenSSL\* was installed to.

Where `default_algorithms` specifies which algorithms supplied by the engine
should be used by default. Specify `ALL` to make all algorithms supplied by the
engine be used by default.

In addition the `qat_section` may contain settings that call custom engine
specific messages. For instance:

    ENABLE_EVENT_DRIVEN_MODE = EMPTY

is functionally equivalent of making the following engine specific message
function call:

    ENGINE_ctrl_cmd(e, "ENABLE_EVENT_DRIVEN_MODE", 0, NULL, NULL, 0);

You should set the setting to `EMPTY` if there are no parameters to pass, or
assign the value that would be passed as the 4th parameter of the equivalent
`ENGINE_ctrl_cmd` call. It should be noted that this mechanism is only useful
for passing simple values at engine initialization time.  You cannot pass 3rd
parameter values, pass complex structures or deal with return values via this
mechanism.

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

By setting up the configuration file as above it is possible for instance to run
the OpenSSL\* speed application to use the Intel&reg; QAT OpenSSL\* Engine
without needing to specify `-engine qatengine` as a command line option.
