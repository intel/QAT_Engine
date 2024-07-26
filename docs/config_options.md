# Intel&reg; QuickAssist Technology OpenSSL\* Engine Build Options

The following is a list of the options that can be used with the
`./configure` command when building the Intel&reg; QAT OpenSSL\* Engine:

### qat_hw options:
```
--with-qat_hw_dir=/path/to/qat_driver
    Specify the path to the source code directory of the Intel(R) QAT Driver.
    This path is needed for compilation in order to locate the Intel(R) QAT
    header files. For example if using Intel(R) QAT Driver package that was
    unpacked to `/QAT` you would use the following setting:
         --with-qat_hw_dir=/QAT

    This option is not required when building against the in-tree driver
    installed via qatlib RPM.

    This option is not required when building for qat_sw.

```
### Building against OpenSSL from source
```
--with-openssl_install_dir=/path/to/openssl_install
    Specify the path to the top level directory where the OpenSSL* was installed to.
    When this path is specified the qatengine.so engine library is copied
    into the folder containing the other dynamic engines during the 'make install'.

    For example if you installed OpenSSL* to its default location of
    `/usr/local/ssl` then you would use the following setting:
    --with-openssl_install_dir=/usr/local/ssl

    If your system already includes OpenSSL 1.1.1 library and devel package this
    option is not required.
    In this case qatengine.so is installed in the system enginesdir
    (eg: /usr/lib64/engine-1.1).

```
### qat_sw options
```
--enable-qat_sw/--disable-qat_sw
    Enable/Disable qat_sw acceleration. This flag needs to be enabled to utilize
    qat_sw acceleration. This flag when enabled uses Intel(R) Crypto
    Multi-buffer and Intel(R) Multi-buffer crypto for IPsec library and headers
    from the default path (/usr/local and /usr/ respectively). If the crypto_mb
    and IPSec_MB libraries are installed in the path other than default then use
    `--with-qat_sw_crypto_mb_install_dir` and `--with-qat_sw_ipsec_mb_install_dir`
    to set the crypto_mb and ipsec_mb libraries install dir respectively. (disabled by default).

--disable-qat_hw
    Disable Intel(R) QAT Hardware acceleration. This flag needs to be enabled if
    the system has both QAT Hardware and QAT Software Multi-buffer capabilities
    and the in-tree driver is installed in the system via `qatlib`
    RPM where use of QAT SW acceleration over QAT HW is preferred. In case of
    the in-tree driver even though QAT SW acceleration is enabled via
    use of the '--enable-qat_sw' option, if both capabilities are
    available (both QAT HW or QAT SW) then QAT HW acceleration will
    be used by default. However, use of this `--disable-qat_hw` option will
    force the use of QAT SW acceleration.

```

### Optional
```
--with-openssl_dir=/path/to/openssl
    Specify the path to the top level of the OpenSSL* source code.  This path
    is only needed to regenerate engine specific error source files using the
    mkerr.pl script from the OpenSSL source. This option needs to be used
    if there is any new error message added in the QAT Engine source files
    and the error files will get updated using the mkerr.pl script. The default
    if not provided will build QAT Engine from the existing error files
    e_qat_err.c, e_qat_err.h & e_qat.txt in the QAT Engine dir which is
    generated from OpenSSL release mentioned in the github release page.
    For example if you cloned the OpenSSL* Github* repository from within `/`
    then you would use the following setting:
    --with-openssl_dir=/openssl

--with-qat_hw_install_dir=/path/to/qat_driver/build
    Specify the path to the location of the built Intel(R) QAT Hardware Driver
    library  files. This path is needed in order to link to the userspace
    libraries of the Intel(R) QAT Hardware Driver.
    The default if not specified is to use the path specified by --with-qat_hw_dir
    with '/build' appended.  You only need to specify this parameter if the
    driver library files have been built somewhere other than the default.

--with-qat_sw_crypto_mb_install_dir=/path/to/crypto_mb install location
    Specify the path of the built Intel(R) Crypto Multi-buffer library
    (crypto_mb). This path is needed in order to link to the crypto_mb
    library. The default if not specified is to use the standard
    installation path which is '/usr/local'.

    You only need to specify this parameter if the Intel(R) crypto_mb
    library files have been built somewhere other than the default.

--with-qat_sw_ipsec_mb_install_dir=/path/to/ipsec_mb install location
    Specify the path of the built Intel(R) Multi-buffer crypto for IPsec
    library (IPSec_mb). This path is needed in order to link to the IPsec_MB
    library. The default if not specified is to use the standard
    installation path which is '/usr'.

    You only need to specify this parameter if the Intel(R) IPSec_MB
    library files have been built somewhere other than the default.

--enable-qat_hw_contig_mem
    Enables build against the qat_contig_mem driver supplied within
    QAT Engine instead of the USDM component distributed with the Intel(R) QAT
    Driver (disabled by default).

--with-qat_hw_usdm_dir=/path/to/usdm/directory
    Specify the path to the location of the USDM component. The default if not
    specified is to use the path specified by '--with-qat_hw_dir' with
    '/quickassist/utilities/libusdm_drv' appended.  You only need to
    specify this parameter if using the USDM component, and if the path to it
    is different from the default.

--enable-qat_provider
    Enables Provider support instead of engine for OpenSSL. Valid only
    when built against OpenSSL 3.0, default if not specified will use engine
    interface. Currently RSA, ECDSA, ECDH, ECX and AES-GCM algorithms are
    only supported (disabled by default).

--enable-qat_fips
    Enables FIPS support when provider is enabled. Valid only
    when built against OpenSSL 3.0 along with the flag `--enable-qat_provider`,
    (disabled by default).

--disable-qat_hw_rsa/--enable-qat_hw_rsa
    Disable/Enable Intel(R) QAT Hardware RSA acceleration (enabled by default).

--disable-qat_hw_dsa/--enable-qat_hw_dsa
    Disable/Enable Intel(R) QAT Hardware DSA acceleration (enabled by default).

--disable-qat_hw_dh/--enable-qat_hw_dh
    Disable/Enable Intel(R) QAT Hardware DH acceleration (enabled by default).

--disable-qat_hw_ecdh/--enable-qat_hw_ecdh
    Disable/Enable Intel(R) QAT Hardware ECDH acceleration (enabled by default).

--disable-qat_hw_ecdsa/--enable-qat_hw_ecdsa
    Disable/Enable Intel(R) QAT Hardware ECDSA acceleration (enabled by default).

--disable-qat_hw_ciphers/--enable-qat_hw_ciphers
    Disable/Enable Intel(R) QAT Hardware Chained Cipher acceleration
    (enabled by default).

--disable-qat_hw_prf/--enable-qat_hw_prf
    Disable/Enable Intel(R) QAT Hardware PRF acceleration (enabled by default).

--disable-qat_hw_ecx/--enable-qat_hw_ecx
    Disable/Enable Intel(R) QAT Hardware X25519/X448 acceleration (enabled by default).

--disable-qat_hw_hkdf/--enable-qat_hw_hkdf
    Disable/Enable Intel(R) QAT Hardware HKDF acceleration (disabled by default).

--disable-qat_hw_gcm/--enable-qat_hw_gcm
    Disable/Enable Intel(R) QAT Hardware AES-GCM acceleration (disabled by default).

--disable-qat_hw_ccm/--enable-qat_hw_ccm
    Disable/Enable Intel(R) QAT Hardware AES-CCM acceleration (enabled by default).

--disable-qat_hw_sm4_cbc/--enable-qat_hw_sm4_cbc
    Disable/Enable Intel(R) QAT Hardware SM4-CBC acceleration.(disabled by default)
    This flag is valid only on 4xxx(QAT gen 4 devices) as the support is not available
    for earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.) and QAT Engine
    is built with Tongsuo only

--disable-qat_hw_sha3/--enable-qat_hw_sha3
    Disable/Enable Intel(R) QAT Hardware SHA-3 acceleration (disabled by default).
    This flag is valid only on 4xxx(QAT gen 4 devices) as the support is not available
    for earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.)

--disable-qat_hw_sm3/--enable-qat_hw_sm3
    Disable/Enable Intel(R) QAT Hardware SM3 acceleration (disabled by default).
    This flag is valid only on 4xxx(QAT gen 4 devices) as the support is not available
    for earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.)

--disable-qat_hw_sm2/--enable-qat_hw_sm2
    Disable/Enable Intel(R) QAT Hardware SM2 acceleration (disabled by default).
    This flag is valid only on 4xxx(QAT gen 4 devices) as the support is not available
    for earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.)

--disable-qat_hw_chachapoly/--enable-qat_hw_chachapoly
    Disable/Enable Intel(R) QAT Hardware CHACHA20-POLY1305 acceleration (disabled by default).
    This flag is valid only on 4xxx(QAT gen 4 devices) as the support is not available
    for earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.)

--disable-qat_sw_gcm/--enable-qat_sw_gcm
    Disable/Enable Intel(R) QAT Software vectorized AES-GCM acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    flag '--enable-qat_sw' and IPSec_mb library is installed in the system
    (enabled by default if qat_sw is enabled).

--disable-qat_sw_rsa/--enable-qat_sw_rsa
    Disable/Enable Intel(R) QAT Software RSA acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    '--enable-qat_sw' (enabled by default if qat_sw is enabled).

--disable-qat_sw_ecx/--enable-qat_sw_ecx
    Disable/Enable Intel(R) QAT Software X25519 acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    '--enable-qat_sw' (enabled by default if qat_sw is enabled).

--disable-qat_sw_ecdsa/--enable-qat_sw_ecdsa
    Disable/Enable Intel(R) QAT Software ECDSA P-256/P-384 acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    '--enable-qat_sw' (enabled by default if qat_sw is enabled).

--disable-qat_sw_ecdh/--enable-qat_sw_ecdh
    Disable/Enable Intel(R) QAT Software ECDH P-256/P-384/SM2 acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    '--enable-qat_sw' (enabled by default if qat_sw is enabled).

--disable-qat_sw_sm2/--enable-qat_sw_sm2
    Disable/Enable Intel(R) QAT Software ECDSA SM2 acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    '--enable-qat_sw' (enabled by default if qat_sw is enabled).

--disable-qat_sw_sm3/--enable-qat_sw_sm3
    Disable/Enable Intel(R) QAT Software SM3 acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the flag
    '--enable-qat_sw' (disabled by default).

--disable-qat_sw_sm4_cbc/--enable-qat_sw_sm4_cbc
    Disable/Enable Intel(R) QAT Software SM4-CBC acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the
    flag '--enable-qat_sw' and QAT Engine is built with Tongsuo only
    (disabled by default if qat_sw is enabled).

--disable-qat_sw_sm4_gcm/--enable-qat_sw_sm4_gcm
    Disable/Enable Intel(R) QAT Software SM4-GCM acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the
    flag '--enable-qat_sw' and QAT Engine is built with Tongsuo only
    (disabled by default if qat_sw is enabled).

--disable-qat_sw_sm4_ccm/--enable-qat_sw_sm4_ccm
    Disable/Enable Intel(R) QAT Software SM4-CCM acceleration.
    This flag is valid only when QAT SW acceleration is enabled using the
    flag '--enable-qat_sw' and QAT Engine is built with Tongsuo only
    (disabled by default if qat_sw is enabled).

--enable-qat_small_pkt_offload
    Enable the acceleration of small packet cipher operations to Intel(R) QAT
    Hardware. When disabled, these operations are performed using the CPU
    (disabled by default).

--enable-qat_warnings
    Enable warnings to aid debugging. Warning: This option should never
    be left on in a production environment as it may introduce side channel
    timing attack vulnerabilities (disabled by default).

--enable-qat_debug
    Enable debug output to aid debugging. This will also enable the
    warning messages above. Warning: This option should never be enabled in a
    production environment as it may output private key information to the
    console/logs and may also introduce side channel timing attack
    vulnerabilities (disabled by default).

--enable-qat_mem_warnings
    Enable warnings from the userspace memory management code to aid
    debugging. Warning: This option should never be left on in a production
    environment as it may introduce side channel timing attack vulnerabilities
    (disabled by default).

--enable-qat_mem_debug
    Enable debug output from the userspace memory management code to
    aid debugging. This will also enable the warning messages above. This
    option produces quite verbose output hence why it is separate to the
    standard debug. Warning: This option should never be enabled in a
    production environment as it may output private key information to the
    console/logs and may also introduce side channel timing attack
    vulnerabilities (disabled by default).

--with-qat_debug_file=/file/and/path/to/log/qat/debug/to
    This option turns on logging to a file instead of to stderr. It works with
    any combination of the following flags:
      --enable-qat_warnings
      --enable-qat_debug
      --enable-qat_mem_warnings
      --enable-qat_mem_debug
    The option should specify the full absolute path and filename that you would
    like to log to. The directory needs to be writable by the user the process
    is running as, and the log file can get very big, very quickly.
    The existing log file will be replaced rather than appended to on each run
    of the application. If the file cannot be opened for writing then the
    logging will default to output to stderr.
    As with the other logging options this option should never be enabled in a
    production environment as private key information and plaintext data will
    be logged to the file (logging to file is disabled by default).

--with-qat_engine_id="<engine_id>"
   This option needs to be specified if you want to use an engine id other than
   the default which is now "qatengine" (previously it was "qat"). This option
   can be used to set engine id as "qat" for application that still uses older
   engine id within the application(disabled by default).

--enable-qat_hw_multi_thread
    Enable an alternative way of managing within userspace the pinned
    contiguous memory allocated by the qat_contig_mem driver. This alternative
    method will give improved performance in a multi-threaded environment by
    making the slab pools thread local to avoid locking between threads.
    Although this can give better performance there are several drawbacks such
    as the memory slabs will be utilized less efficiently, and you cannot
    allocate in one thread and free in another thread.  Running in this mode
    also does not support processes that fork (disabled by default).

--enable-qat_plock
    Enables Plock optimization within QAT Engine which is an alternative to
    pthread's rwlock for multithread application. This flag when enabled uses
    plock using preload as mentioned in QAT Engine install instructions and
    improves performance for higher number of threads (disabled by default).

--enable-qat_ntls
    Enable ntls in engine for handing NTLS requests which is needed for SMx
    with Tongsuo (disabled by default).

--enable-qat_insecure_algorithms
    Enables insecure algorithms RSA < 2048, DH, DSA, ECDH curves with bitlen
    < 256, ECDSA Curves with bitlen < 256, AES128-CBC-HMAC-SHA1,
    AES256-CBC-HMAC-SHA1 & SHA3-224. These insecure algorithms are disabled
    by default. QAT HW driver version v1.7 needs to be built with the flag
    `./configure --enable-legacy-algorithms` to enable these algorithms
    (disabled by default).

--disable-qat_hw_lenstra_protection
    Disable protection against Lenstra attack (CVE-2017-5681)
    (protection is enabled by default). The RSA-CRT implementation in the
    Intel(R) QAT OpenSSL* Engine, for OpenSSL* versions prior to v0.5.19,
    may allow remote attackers to obtain private RSA keys by conducting a
    Lenstra side-channel attack.  From version v0.5.19 onward, protection
    against this form of attack is effected by performing a Verify/Encrypt
    operation after the Sign/Decrypt operation, and if a failure is detected
    then re-running the Sign/Decrypt operation using the CPU.
    However, future releases of Intel(R) QAT driver code or firmware may
    effect this protection instead, in which case the Intel(R) QAT OpenSSL*
    Engine code-based protection would no longer be required and this
    configuration option should then be selected.
    For further information, please refer to:-
    https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00071&languageid=en-fr
    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5681

--enable-qat_hw_lenstra_verify_hw
    Enable Lenstra Verify using QAT HW instead of OpenSSL Software method.
    (disabled by default).

--disable-qat_auto_engine_init_on_fork
    Disable the engine from being initialized automatically following a
    fork operation. This is useful in a situation where you want to tightly
    control how many instances are being used for processes. For instance if an
    application forks to start a process that does not utilize QAT currently
    the default behaviour is for the engine to still automatically get started
    in the child using up an engine instance. After using this flag either the
    engine needs to be initialized manually using the engine message:
    INIT_ENGINE or will automatically get initialized on the first QAT crypto
    operation. The initialization on fork is enabled by default.

--enable-qat_sw_heuristic_timeout
    Enable self tuning of the timeout in the polling thread in the
    Intel(R) QAT SW. This flag is valid only in case of QAT SW
    (disabled by default).

--enable-qat_cycle_counts
    Enable cycle count measurement in the qat_sw acceleration.
    This support is only extended to qat_sw acceleration code path
    (disabled by default).

--with-cc-opt="parameters"
    Sets additional parameters that will be added to the CFLAGS variable at
    compile time.

--with-ld-opt="parameters"
    Sets additional parameters that will be used during linking.

```
