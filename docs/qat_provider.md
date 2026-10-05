# QAT Provider Interface

The Intel&reg; QAT Provider (`qatprovider`) is the recommended integration point
for OpenSSL 3.x applications.
QAT Provider is built by default. The legacy QAT Engine (`qatengine`) can be
enabled with `--enable-qat_engine`.

As OpenSSL ENGINE support is removed in OpenSSL 4.0, `qatprovider` is the supported
QAT integration path for OpenSSL 4.0 and later.

For ML-KEM and ML-DSA offload through IPsec MB, and hybrid PQC configurations,
see [PQC and Hybrid PQC Support](qat_provider_pqc.md).

## Contents

* [Provider Priority and Loading](#provider-priority-and-loading)
* [Example QAT Provider (`qatprovider`) Test Commands](#example-qat-provider-qatprovider-test-commands)
* [Provider Runtime Parameters](#provider-runtime-parameters-ossl_provider_get_params)
* [Application Integration](#application-integration)
  * [Configuring through openssl.cnf](#configuring-through-opensslcnf)
  * [Parameter names](#parameter-names)
  * [How parameters are exchanged](#how-parameters-are-exchanged)
  * [Configuration sources and precedence](#configuration-sources-and-precedence)
  * [Initialization sequence](#initialization-sequence)
  * [Polling modes](#polling-modes)
  * [External polling](#external-polling)
  * [Heuristic polling](#heuristic-polling)
  * [openssl.cnf reference](#opensslcnf-reference)
  * [Migrating from the OpenSSL ENGINE interface](#migrating-from-the-openssl-engine-interface)
  * [Reference implementation](#reference-implementation)
* [FIPS 140-3 Certification](#fips-140-3-certification)

## Provider Priority and Loading

If `qatprovider.so` is not installed in the default OpenSSL modules directory
(`<openssl-install>/lib64/ossl-modules/`), add
`-provider-path /path/to/ossl-modules` before `-provider qatprovider`.

When loading `qatprovider` explicitly, also load the OpenSSL `default` provider:

- Add `-provider default` in command-line invocations, or
- Activate `[default_sect]` in `openssl.cnf`.

The `default` provider supplies algorithms and operations that are not offloaded
by QAT. Without it, commands can fail with missing algorithm errors.

Loading `qatprovider` does not automatically give it the highest fetch priority.
When QAT_HW or QAT_SW offload is supported and enabled, applications should use
the optional property query `?provider=qatprovider` to prefer `qatprovider` for
the algorithms it implements while retaining the `default` provider for other
algorithms. See the [reference implementation](#reference-implementation).

## Example QAT Provider (`qatprovider`) Test Commands

* QAT_HW
     ./openssl speed -provider qatprovider -provider default -elapsed -async_jobs 72 rsa2048
* QAT_SW
     ./openssl speed -provider qatprovider -provider default -elapsed -async_jobs 8 rsa2048

**RSA Sign/Verify:**
```
./openssl genrsa -provider qatprovider -provider default -out rsa_key.pem 2048
./openssl dgst -provider qatprovider -provider default -sha256 -sign rsa_key.pem -out sig.bin plain.txt
./openssl dgst -provider qatprovider -provider default -sha256 -verify <(./openssl rsa -in rsa_key.pem -pubout) -signature sig.bin plain.txt
```

**ECDSA Sign/Verify (P-256):**
```
./openssl genpkey -provider qatprovider -provider default -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_key.pem
./openssl dgst -provider qatprovider -provider default -sha256 -sign ec_key.pem -out ec_sig.bin plain.txt
./openssl dgst -provider qatprovider -provider default -sha256 -verify <(./openssl pkey -in ec_key.pem -pubout) -signature ec_sig.bin plain.txt
```

**AES-GCM:**
```
./openssl speed -provider qatprovider -provider default -elapsed -evp aes-256-gcm
```

**TLS Handshake (s_server / s_client):**
```
# Server
./openssl s_server -provider qatprovider -provider default -cert server.crt -key server.key -port 4433 &
# Client
./openssl s_client -provider qatprovider -provider default -connect localhost:4433
```

## Provider Runtime Parameters (OSSL_PROVIDER_get_params)

The Provider exposes runtime controls through `OSSL_PROVIDER_get_params()`.
The parameter names below are the exact wire names used by `qatprovider`.
For the calling convention, required ordering, and polling, see
[Application Integration](#application-integration). For the Engine message
equivalents, see
[Migrating from the OpenSSL ENGINE interface](#migrating-from-the-openssl-engine-interface).

| Parameter name | Type | Access | Description |
| :--- | :---: | :---: | :--- |
| `qat_enable_external_polling` | int | Read/Write | Enable external polling mode. Effective only before Provider HW init is committed. Read-back returns effective value. |
| `qat_enable_heuristic_polling` | int | Read/Write | Enable heuristic polling mode. Requires external polling to be enabled first. Effective only before Provider HW init is committed. |
| `qat_enable_sw_fallback` | int | Read/Write | Enable (`1`) or disable (`0`) software fallback in QAT_HW builds. |
| `qat_internal_poll_interval` | int | Read/Write | Internal polling interval in ns, valid range `1..1000000`. |
| `qat_init_provider` | int | Command/Status | Write non-zero to trigger deferred Provider initialization. Read-back returns init result (`1` success, `0` failure). |
| `qat_poll` | int | Command/Status | Trigger one polling cycle and return status (`1` serviced or no work, `0` hard failure, `-1` not ready). |
| `qat_heartbeat_poll` | int | Read-only | Heartbeat status for device health checks (`-1` when not ready / unavailable). |
| `qat_num_asym_requests_in_flight` | int | Read-only | Number of asymmetric in-flight requests. |
| `qat_num_kdf_requests_in_flight` | int | Read-only | Number of KDF in-flight requests. |
| `qat_num_cipher_requests_in_flight` | int | Read-only | Number of cipher in-flight requests. |
| `qat_num_asym_mb_items_in_queue` | int | Read-only | Number of asymmetric multibuffer queued items. |
| `qat_num_kdf_mb_items_in_queue` | int | Read-only | Number of KDF multibuffer queued items. |
| `qat_num_sym_mb_items_in_queue` | int | Read-only | Number of symmetric multibuffer queued items. |
| `qat_small_pkt_offload_threshold` | utf8 string | Write-only | Per-algorithm threshold string in the format `algo:size,algo2:size2`. |
| `qat_configured_from_cnf` | int | Read-only | Sentinel: `1` when polling mode came from `openssl.cnf`, otherwise `0`. |
| `qat_hw_asym_threshold` | int | Read/Write | Heuristic poll threshold for QAT_HW asymmetric queue. Defaults to `48`. |
| `qat_hw_sym_threshold` | int | Read/Write | Heuristic poll threshold for QAT_HW symmetric queue. Defaults to `24`. |
| `qat_sw_threshold` | int | Read/Write | Heuristic poll threshold for QAT_SW queue. Defaults to `8`. |

Notes:
- `qat_small_pkt_offload_threshold` uses algorithm names as keys. Invalid
  algorithm names or malformed values are ignored with warnings.
- QAT_HW AES-GCM uses a default small-packet threshold of 4096 bytes. AES-GCM
  payloads of 4096 bytes or less use the OpenSSL software implementation;
  larger payloads are offloaded to QAT_HW. This threshold is initialized from
  `CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD_HW_GCM` and can be changed through
  `qat_small_pkt_offload_threshold`.
- The small packet threshold parameter is not applied when built with
  `--enable-qat_small_pkt_offload`; in that build, small AES-GCM packets are
  also offloaded to QAT_HW.
- For `qat_hw_asym_threshold`, `qat_hw_sym_threshold`, and `qat_sw_threshold`,
  pass values `>= 1` to update. A value of `0` is treated as read-back only.

## Application Integration

This section is for developers integrating `qatprovider` into an application
&mdash; a proxy, load balancer, web server or any other OpenSSL\* 3.x/4.x
program that wants to drive QAT offload directly rather than rely on defaults.
It applies across applications. For integration symptoms and likely causes, see
[Troubleshooting](troubleshooting.md#qat-provider-application-integration).

### Configuring through openssl.cnf

Set QAT options in the provider section of `openssl.cnf`. `qatprovider` reads
and applies them when it loads, before the application can supply settings.
The application reads the effective polling configuration from the provider
and starts a poller if external or heuristic polling is selected.

This section uses `openssl.cnf` for QAT configuration. If the configuration file
has no QAT settings, an application can instead supply them at start-up through
`OSSL_PROVIDER_get_params()` before provider initialization. See the
[reference implementation](#reference-implementation) for an application that
supports both configuration sources.

### Parameter names

Parameters are identified by string name. Defining them in one application
header avoids repeating string literals at each call site. If a name is
misspelled, `OSSL_PARAM_locate()` returns `NULL` while
`OSSL_PROVIDER_get_params()` can still report success, so the setting is not
applied.

The examples in this section use the following definitions.

```c
/* Provider identity and fetch configuration */
#define QAT_PROVIDER_NAME                    "qatprovider"
#define QAT_PROV_DEFAULT_PROPERTY_QUERY      "?provider=qatprovider"

/* Polling configuration */
#define QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING  "qat_enable_external_polling"
#define QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING "qat_enable_heuristic_polling"
#define QAT_PROV_PARAM_ENABLE_SW_FALLBACK       "qat_enable_sw_fallback"
#define QAT_PROV_PARAM_INTERNAL_POLL_INTERVAL   "qat_internal_poll_interval"

/* Lifecycle and runtime commands */
#define QAT_PROV_PARAM_INIT_PROVIDER         "qat_init_provider"
#define QAT_PROV_PARAM_POLL                  "qat_poll"
#define QAT_PROV_PARAM_HEARTBEAT_POLL        "qat_heartbeat_poll"

/* In-flight telemetry */
#define QAT_PROV_PARAM_NUM_ASYM_REQUESTS_IN_FLIGHT   "qat_num_asym_requests_in_flight"
#define QAT_PROV_PARAM_NUM_KDF_REQUESTS_IN_FLIGHT    "qat_num_kdf_requests_in_flight"
#define QAT_PROV_PARAM_NUM_CIPHER_REQUESTS_IN_FLIGHT "qat_num_cipher_requests_in_flight"
#define QAT_PROV_PARAM_NUM_ASYM_MB_ITEMS_IN_QUEUE    "qat_num_asym_mb_items_in_queue"
#define QAT_PROV_PARAM_NUM_KDF_MB_ITEMS_IN_QUEUE     "qat_num_kdf_mb_items_in_queue"
#define QAT_PROV_PARAM_NUM_SYM_MB_ITEMS_IN_QUEUE     "qat_num_sym_mb_items_in_queue"

/* Tuning and introspection */
#define QAT_PROV_PARAM_SMALL_PKT_OFFLOAD_THRESHOLD "qat_small_pkt_offload_threshold"
#define QAT_PROV_PARAM_HW_ASYM_THRESHOLD     "qat_hw_asym_threshold"
#define QAT_PROV_PARAM_HW_SYM_THRESHOLD      "qat_hw_sym_threshold"
#define QAT_PROV_PARAM_SW_THRESHOLD          "qat_sw_threshold"
#define QAT_PROV_PARAM_CONFIGURED_FROM_CNF   "qat_configured_from_cnf"

/* Status codes returned by the command parameters */
#define QAT_PROV_INIT_SUCCESS                1
#define QAT_PROV_INIT_FAILURE                0
#define QAT_PROV_POLL_SERVICED               1
#define QAT_PROV_POLL_FAILED                 0
#define QAT_PROV_POLL_NOT_READY              (-1)
#define QAT_PROV_HEARTBEAT_HEALTHY           0
#define QAT_PROV_HEARTBEAT_UNAVAILABLE       (-1)
```

### How parameters are exchanged

`qatprovider` does not implement `OSSL_FUNC_PROVIDER_SET_PARAMS`. Every
parameter &mdash; including those that configure or command the provider
&mdash; is exchanged through a single `OSSL_PROVIDER_get_params()` call.

The caller pre-fills the `OSSL_PARAM` value. The provider consumes it, then
writes the effective value or a status code back into the same `OSSL_PARAM`.
A parameter absent from the array is never touched.

```c
int ext = 1;
OSSL_PARAM p[2];

p[0] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING, &ext);
p[1] = OSSL_PARAM_construct_end();

if (!OSSL_PROVIDER_get_params(prov, p))
    return -1;

/* ext now holds the EFFECTIVE value, which may differ from what was written. */
```

#### How written values are interpreted

Some parameters treat `0` as a read-back request, while others apply it as a
setting. Check the behavior for each parameter group when sending values.

| Parameter group | Written value behaviour |
| :--- | :--- |
| `QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING`, `QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING` | Non-zero values enable polling. Writing `0` reads the effective value; it does not disable polling. Once enabled, the mode cannot be turned off at runtime. |
| `QAT_PROV_PARAM_ENABLE_SW_FALLBACK` | Writing `0` disables software fallback. |
| `QAT_PROV_PARAM_HW_ASYM_THRESHOLD`, `QAT_PROV_PARAM_HW_SYM_THRESHOLD`, `QAT_PROV_PARAM_SW_THRESHOLD` | Values `>= 1` are applied. A written `0` is a read-back request. |
| `QAT_PROV_PARAM_INIT_PROVIDER`, `QAT_PROV_PARAM_POLL` | Commands. Write non-zero to act; read back a status code. |
| `QAT_PROV_PARAM_SMALL_PKT_OFFLOAD_THRESHOLD` | Write-only. The provider never writes this parameter back. |
| `qat_num_*` counters, `QAT_PROV_PARAM_HEARTBEAT_POLL`, `QAT_PROV_PARAM_CONFIGURED_FROM_CNF` | Read-only. |

#### Configuration is fixed after initialization

Configuration parameters take effect only **before** QAT hardware
initialization is committed. Afterwards, writes are ignored and only logged;
changing them requires a process restart.

This applies to `QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING`,
`QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING`,
`QAT_PROV_PARAM_ENABLE_SW_FALLBACK` and
`QAT_PROV_PARAM_INTERNAL_POLL_INTERVAL`.

Push all configuration parameters **before** `QAT_PROV_PARAM_INIT_PROVIDER`,
and before any cryptographic operation. Passing them in one array together with
`QAT_PROV_PARAM_INIT_PROVIDER` is the recommended pattern: the provider
processes them in a fixed order with initialization last.

### Configuration sources and precedence

QAT settings can come from two places:

1. The provider section of `openssl.cnf`.
2. The application, via `OSSL_PROVIDER_get_params()`.

When both sources provide QAT settings, the configuration in `openssl.cnf`
takes precedence over application-supplied settings. The file is parsed during
`OSSL_provider_init()`, so the polling mode is selected and committed while the
provider is loading, before the application can supply its settings. Later
attempts to change the polling mode are rejected because configuration is
already committed.

Read `QAT_PROV_PARAM_CONFIGURED_FROM_CNF` to identify the configuration source:

```c
int configured_from_cnf = 0;
OSSL_PARAM p[2];

p[0] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_CONFIGURED_FROM_CNF,
                                &configured_from_cnf);
p[1] = OSSL_PARAM_construct_end();
OSSL_PROVIDER_get_params(prov, p);

/* configured_from_cnf == 1: openssl.cnf supplied QAT settings.
 * configured_from_cnf == 0: the application can supply them. */
```

> **Note**
> `QAT_PROV_PARAM_CONFIGURED_FROM_CNF` indicates that `openssl.cnf` supplied
> QAT settings, not necessarily a polling mode. A provider section containing
> only `qat_small_pkt_offload_threshold`, for example, still reports `1` and
> commits internal polling. If QAT settings are in `openssl.cnf`, specify
> `qat_poll_mode` explicitly. Otherwise, leave QAT settings out of the file
> and configure them from the application.

### Initialization sequence

Initialize once per process at start-up, before accepting traffic. Follow the
sequence below so configuration is applied before provider initialization.

When QAT settings come from `openssl.cnf`, the application reads the polling
configuration that the provider already applied, rather than supplying its own.

```c
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static OSSL_PROVIDER *qat_prov;
static int            qat_external_polling;
static int            qat_heuristic_polling;

int qat_setup(void)
{
    OSSL_PARAM     p[5];
    int            configured_from_cnf = 0;
    int            ext = 0, heur = 0, init = 1;
    unsigned char  seed;

    /* 1. Keep the OpenSSL default provider available for algorithms that
     *    qatprovider does not implement. */
    if (!OSSL_PROVIDER_available(NULL, "default")
            && OSSL_PROVIDER_load(NULL, "default") == NULL)
        return -1;

    /* 2. Resolve qatprovider. OSSL_PROVIDER_load() returns a reference even
     *    when openssl.cnf already activated it. */
    qat_prov = OSSL_PROVIDER_load(NULL, QAT_PROVIDER_NAME);
    if (qat_prov == NULL)
        return -1;    /* see Troubleshooting: an invalid qat_poll_mode in
                       * openssl.cnf prevents the provider from loading */

    /* 3. Instantiate the default libctx DRBG BEFORE biasing the fetch query.
     *    qatprovider does not implement a DRBG, so a biased query issued
     *    first makes the DRBG fetch fail. One RAND_bytes() call is enough. */
    if (RAND_bytes(&seed, sizeof(seed)) != 1)
        return -1;

    /* 4. Prefer qatprovider for the algorithms it implements. Otherwise,
     *    symmetric algorithms resolve to the default provider without QAT
     *    offload. The leading '?' keeps unimplemented algorithms available
     *    from the default provider. */
    if (!EVP_set_default_properties(NULL, QAT_PROV_DEFAULT_PROPERTY_QUERY))
        return -1;

    /* 5. Read the committed configuration. Writing 0 to the two polling
     *    parameters is a read-back request, so this call changes nothing and
     *    returns the effective values. */
    p[0] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_CONFIGURED_FROM_CNF,
                                    &configured_from_cnf);
    p[1] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING,
                                    &ext);
    p[2] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING,
                                    &heur);
    p[3] = OSSL_PARAM_construct_end();
    if (!OSSL_PROVIDER_get_params(qat_prov, p))
        return -1;

    if (!configured_from_cnf) {
        /* openssl.cnf carries no QAT settings. Either add them, or supply
         * them from the application before initialization. */
        return -1;
    }

    qat_external_polling  = ext;
    qat_heuristic_polling = heur;

    /* 6. Write INIT_PROVIDER even when openssl.cnf has already initialised
     *    QAT. This registers the process as the external poller (see
     *    "External polling"). The write is idempotent. */
    p[0] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_INIT_PROVIDER, &init);
    p[1] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_get_params(qat_prov, p)
            || init != QAT_PROV_INIT_SUCCESS)
        return -1;

    /* 7. Arm the poller matching the configured mode. Nothing to arm when
     *    openssl.cnf selected internal polling. */
    if (qat_external_polling)
        qat_arm_poller(qat_heuristic_polling);

    return 0;
}
```

The matching `openssl.cnf` for this example selects external polling:

    [ qat_prov_section ]
    module = /usr/local/lib64/ossl-modules/qatprovider.so
    activate = 1
    qat_poll_mode = external

  Activating `qatprovider` in `openssl.cnf` loads and configures the provider, but
  does not set the application's fetch properties. The application must still use
  `?provider=qatprovider`, as shown in step 4 above, to prefer QAT implementations.

If your application forks workers, run this in the worker after the fork.

### Polling modes

QAT completions must be collected by polling. Three modes are available, and
they are mutually exclusive.

| Mode | Who polls | When to use |
| :--- | :--- | :--- |
| Internal (default) | A polling thread started by `qatprovider` | Simple applications with no thread-placement constraints. No integration work required. |
| External | The application, from its own event loop | Applications that pin threads to cores, run a run-to-completion loop, or need deterministic completion handling. |
| Heuristic | The application, batched by in-flight depth | Same as external, but reduces polling overhead under sustained load by waiting for a worthwhile batch. |

Heuristic polling is a refinement of external polling, not an alternative to
it: enabling heuristic requires external polling to already be enabled, and
`qatprovider` reports both as active.

Selecting external or heuristic polling means **`qatprovider` does not start a
polling thread**. The application becomes solely responsible for calling
`QAT_PROV_PARAM_POLL`, or requests will never complete.

### External polling

#### Registering as the poller

> **Warning**
> If external or heuristic polling is selected and the application never writes
> `QAT_PROV_PARAM_INIT_PROVIDER` or `QAT_PROV_PARAM_POLL`, QAT asynchronous
> offload is **disabled for the lifetime of the process** and every request
> falls back to OpenSSL\* software. The condition is reported once on the QAT
> log stream and is otherwise silent: no error is returned, handshakes succeed,
> and throughput does not reflect QAT offload.

The provider considers an external poller registered once the application has
written `QAT_PROV_PARAM_INIT_PROVIDER` or `QAT_PROV_PARAM_POLL` at least once.
If a TLS handshake reaches the provider before that happens, the fallback is
permanent for the lifetime of the process.

Write `QAT_PROV_PARAM_INIT_PROVIDER` during start-up before accepting traffic,
including when `openssl.cnf` selected the polling mode and the provider is
already initialised. This idempotent call registers the external poller before
cryptographic operations begin.

#### The poll call

```c
void qat_poll_once(void)
{
    int        status = QAT_PROV_POLL_NOT_READY;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_int(QAT_PROV_PARAM_POLL, &status);
    p[1] = OSSL_PARAM_construct_end();

    if (!OSSL_PROVIDER_get_params(qat_prov, p)
            || status != QAT_PROV_POLL_SERVICED) {
        /* Poll failed or the provider is not ready; inspect the QAT log stream. */
        log_error("QAT poll failed (status=%d)", status);
    }
}
```

| Status | Meaning |
| :--- | :--- |
| `QAT_PROV_POLL_SERVICED` (1) | Poll serviced. Also returned when there was nothing to do, and for a benign device retry. |
| `QAT_PROV_POLL_FAILED` (0) | Hard polling failure. |
| `QAT_PROV_POLL_NOT_READY` (-1) | Provider not initialised, or external polling not enabled. |

`QAT_PROV_POLL_SERVICED` does **not** mean work completed, and there is no
"work remaining" indicator. Use the in-flight counters if you need that.

#### Where to call it

Call `QAT_PROV_PARAM_POLL` from a point that executes on every iteration of
your event loop, and additionally from a periodic timer as a backstop. The
timer matters: a completion can arrive when no connection event follows to
drive the loop, and without a backstop that request stalls until the next
unrelated event.

The call is cheap when there is nothing outstanding, so polling
unconditionally is usually simpler and no slower than gating it on a counter
read.

There is no completion file descriptor to add to an event loop. The Engine
interface exposed one through `GET_EXTERNAL_POLLING_FD`; the provider does not,
and event-driven polling is in any case unsupported with the in-tree (qatlib)
driver.

### Heuristic polling

Heuristic polling reduces poll frequency by waiting until a worthwhile batch of
requests has accumulated.

> **Note**
> The threshold parameters are advisory. `qatprovider` stores and returns
> their values so they can be specified in `openssl.cnf`, but the application
> decides when to poll.

The application reads the in-flight counters, compares them against the
thresholds, and decides whether to poll:

```c
static int qat_refresh_counters(int v[6])
{
    static const char *const keys[6] = {
        QAT_PROV_PARAM_NUM_ASYM_REQUESTS_IN_FLIGHT,
        QAT_PROV_PARAM_NUM_KDF_REQUESTS_IN_FLIGHT,
        QAT_PROV_PARAM_NUM_CIPHER_REQUESTS_IN_FLIGHT,
        QAT_PROV_PARAM_NUM_ASYM_MB_ITEMS_IN_QUEUE,
        QAT_PROV_PARAM_NUM_KDF_MB_ITEMS_IN_QUEUE,
        QAT_PROV_PARAM_NUM_SYM_MB_ITEMS_IN_QUEUE,
    };
    OSSL_PARAM p[7];
    size_t     i;

    for (i = 0; i < 6; i++)
        p[i] = OSSL_PARAM_construct_int((char *) keys[i], &v[i]);
    p[6] = OSSL_PARAM_construct_end();

    return OSSL_PROVIDER_get_params(qat_prov, p);
}
```

Threshold selection, following the reference implementation:

* If asymmetric hardware requests are outstanding, use
  `QAT_PROV_PARAM_HW_ASYM_THRESHOLD` (default 48).
* Else if either QAT_SW multi-buffer queue is non-empty, use
  `QAT_PROV_PARAM_SW_THRESHOLD` (default 8). This single knob governs **both**
  the SW asymmetric and SW symmetric queues.
* Else use `QAT_PROV_PARAM_HW_SYM_THRESHOLD` (default 24).

Poll when the total reaches the threshold. Set a maximum deferral, such as two
ticks, to flush a small tail that does not reach the threshold. If the counter
read fails, poll anyway so outstanding completions are still collected.

The counters are **instantaneous gauges for the calling process**, not
cumulative totals, and each read is a fresh snapshot. The
`*_MB_ITEMS_IN_QUEUE` counters describe the QAT_SW multi-buffer queues and read
`0` in a QAT_HW-only build.

### openssl.cnf reference

The keys recognised in the provider section of `openssl.cnf` are **not** the
same strings as the runtime parameters. Applications that generate
configuration files should treat the two sets as distinct.

    [ qat_prov_section ]
    module = /usr/local/lib64/ossl-modules/qatprovider.so
    activate = 1
    qat_poll_mode = external
    qat_offload_mode = async
    qat_sw_fallback = on
    qat_hw_asym_threshold = 48
    qat_hw_sym_threshold = 24
    qat_sw_threshold = 8
    qat_small_pkt_offload_threshold = AES-256-GCM:8192

| Key | Values | Notes |
| :--- | :--- | :--- |
| `qat_poll_mode` | `internal`, `external`, `heuristic` | Takes precedence over the raw polling keys. See the note below. |
| `qat_offload_mode` | `sync`, `async` | `sync` with external or heuristic polling is contradictory and is reported as a warning; the effective mode is async. |
| `qat_sw_fallback` | `on`, `off`, `1`, `0` | QAT_HW only. |
| `qat_poll_interval` | 1..1000000 | Internal polling interval in nanoseconds. Default 10000. Out-of-range values are rejected with a warning. |
| `qat_hw_asym_threshold`, `qat_hw_sym_threshold`, `qat_sw_threshold` | integer `>= 1` | Advisory; relayed to the application. |
| `qat_small_pkt_offload_threshold` | `algo:size,algo2:size2` | Algorithm short names as accepted by `OBJ_sn2nid()`. |
| `enable_external_polling`, `enable_heuristic_polling` | `0`, `1` | Raw polling keys, applied **only** when `qat_poll_mode` is absent. |
| `enable_sw_fallback` | `0`, `1` | Raw fallback key. Applied regardless of `qat_poll_mode`, after `qat_sw_fallback`; when both fallback keys are present, this value takes precedence. |
| `enable_event_driven_polling`, `qat_epoll_timeout`, `enable_instance_for_thread`, `qat_max_retry_count` | see [Engine Specific Messages](engine_specific_messages.md) | QAT_HW only. Event driven polling is not supported with the in-tree (qatlib) driver. |

> **Note**
> When `qat_poll_mode` is present, the raw `enable_external_polling` and
> `enable_heuristic_polling` keys are ignored with a warning.
>
> An unrecognised `qat_poll_mode` value causes provider initialization to fail:
> `OSSL_PROVIDER_load()` returns `NULL` and TLS set-up fails. This avoids
> selecting internal polling when a different mode was requested. Check any
> generated values against the supported modes above.

### Migrating from the OpenSSL ENGINE interface

| Engine message | Provider parameter |
| :--- | :--- |
| `ENABLE_EXTERNAL_POLLING` | `QAT_PROV_PARAM_ENABLE_EXTERNAL_POLLING` |
| `ENABLE_HEURISTIC_POLLING` | `QAT_PROV_PARAM_ENABLE_HEURISTIC_POLLING` |
| `ENABLE_SW_FALLBACK` | `QAT_PROV_PARAM_ENABLE_SW_FALLBACK` |
| `SET_INTERNAL_POLL_INTERVAL` | `QAT_PROV_PARAM_INTERNAL_POLL_INTERVAL` |
| `INIT_ENGINE` | `QAT_PROV_PARAM_INIT_PROVIDER` |
| `POLL` | `QAT_PROV_PARAM_POLL` |
| `HEARTBEAT_POLL` | `QAT_PROV_PARAM_HEARTBEAT_POLL` |
| `SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD` | `QAT_PROV_PARAM_SMALL_PKT_OFFLOAD_THRESHOLD` |
| `GET_NUM_REQUESTS_IN_FLIGHT` | The `QAT_PROV_PARAM_NUM_*` counters |

Available only through `openssl.cnf`, with no runtime parameter:
`ENABLE_EVENT_DRIVEN_POLLING_MODE`, `DISABLE_EVENT_DRIVEN_POLLING_MODE`,
`SET_EPOLL_TIMEOUT`, `SET_INSTANCE_FOR_THREAD`, `SET_MAX_RETRY_COUNT`.

No provider equivalent: `GET_NUM_CRYPTO_INSTANCES`,
`GET_EXTERNAL_POLLING_FD`, `ENABLE_INLINE_POLLING`, `GET_NUM_OP_RETRIES`,
`DISABLE_QAT_OFFLOAD`, `SET_CONFIGURATION_SECTION_NAME`, `HW_ALGO_BITMAP`,
`SW_ALGO_BITMAP`.

Behavioural differences to account for when porting:

* **In-flight counters.** The Engine returned a pointer to the live counter, so
  a single query could be read repeatedly. The provider returns a snapshot per
  call; a polling loop must re-query on every iteration.
* **Property query.** The OpenSSL ENGINE interface required no fetch configuration. The
  provider does: without
  `EVP_set_default_properties(NULL, QAT_PROV_DEFAULT_PROPERTY_QUERY)`,
  symmetric algorithms silently resolve to the default provider.
* **No polling file descriptor.** Applications that added the Engine's polling
  fd to an event loop must move to a per-iteration poll call plus a timer.

### Reference implementation

A complete, working integration for an event-loop application is the QAT
provider module in the Intel&reg; QAT async mode NGINX\* distribution:

<https://github.com/intel/asynch_mode_nginx>

It demonstrates the lifecycle described here: provider preload and fetch
configuration at start-up, using `openssl.cnf` settings when present,
the ordered configuration push, an event-loop poll hook with a timer backstop,
heuristic batching from the in-flight counters, and heartbeat polling for
software fallback. It also shows a bounded drain of in-flight requests on
worker exit.

The module also contains NGINX\*-specific configuration, timer management and
shutdown logic that is not part of the provider contract. Use it as an example
of the lifecycle described in this section.

## FIPS 140-3 Certification

QAT_Engine v1.3.1 obtained FIPS 140-3 Level 1
certification for the QAT Provider. See
[NIST CMVP Certificate #5032](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5032).

Enable FIPS support for `qatprovider` with the `--enable-qat_fips` configure
option. This option is supported when building against OpenSSL 3.0.8 and later.
When enabled, `qatprovider` performs the required self-tests, integrity tests,
and other FIPS-related operations.

The configure option enables FIPS-compatible Provider functionality. FIPS
compliance can be claimed only when `qatprovider` is used as part of a validated
OpenSSL FIPS configuration.

### Algorithms Supported in FIPS Mode

| Mode | Algorithms |
| :---: | :--- |
| QAT_HW | RSA, ECDSA, ECDH, X25519, X448, DSA, DH, TLS 1.2 KDF (PRF), TLS 1.3 KDF (HKDF), SHA-3, AES-GCM |
| QAT_SW | RSA, ECDSA, ECDH, X25519, SHA-2, AES-GCM |

## Related Documents

* [PQC and Hybrid PQC Support](qat_provider_pqc.md)
* [OpenSSL Configuration](openssl_config.md)
* [Engine Specific Messages](engine_specific_messages.md)
* [Software Fallback](qat_hw.md)
* [Asynchronous Operation and Job Support](async_job.md)
* [Limitations](limitations.md)
* [Troubleshooting](troubleshooting.md)
