# Intel&reg; QuickAssist Technology OpenSSL\* Engine Specific Messages

OpenSSL\* engines support a mechanism whereby custom messages can be defined for
an application to communicate directly with the engine.  These messages are
typically used in two ways:

   1. Firstly in order to set configuration options. These messages are
      typically sent before the engine is initialized. Sending these after
      initialization will typically have no effect.
   2. Secondly in order to control the engine operation. These messages may be
      sent before initialization or after or both.

The custom message mechanism passes a string to identify the message, and uses a
number of parameters to pass information into or out of the engine. It is
defined as follows:

    ENGINE_ctrl_cmd(<Engine>, <Message String>, <Param 3>,
                    <Param 4>, NULL, 0\)

Where:

   - `<Engine>` is a pointer to the Intel&reg; QAT enabled OpenSSL\* Engine.
   - `<Message String>` is a string representing the message type.
   - `<Param 3>` is a long that can be used to pass a number, or a pointer
     can be cast to it.
   - `<Param 4>` is a void pointer used to pass data structures in.
   - The last two parameters are always `NULL` and 0 when used with the Intel&reg;
     QAT OpenSSL\* Engine.

```text
Message String: ENABLE_EXTERNAL_POLLING
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable the external polling mode of operation where
    it becomes the applications responsibility to use the POLL message below to
    check for messages that have been returned from the hardware accelerator.
    It has no parameters or return value.  If required this message must be
    sent after engine creation and before engine initialization.

Message String: POLL
Param 3:        0
Param 4:        pointer to an int
Description:
    This message is used when external polling is enabled to request poll of
    all instances. The status of the request is passed back in the variable
    passed in as Param 4. This message may be sent at any time after engine
    initialization.

Message String: INIT_ENGINE
Param 3:        0
Param 4:        NULL
Description:
    This message is not normally necessary as the engine will get initialized
    either via an ENGINE_init() call or automatically following a fork. This
    message would only be used for performance reasons with an engine compiled
    with --disable-qat_auto_engine_init_on_fork. In that case it may be
    desirable to send this engine message in the child rather than wait for the
    engine to be initialized automatically on the first accelerated crypto
    request.

Message String: SET_INTERNAL_POLL_INTERVAL
Param 3:        unsigned long cast to a long
Param 4:        NULL
Description:
    This message is used to set the interval in nano seconds between polling
    for messages coming back from the hardware accelerator. The value should be
    passed in as Param 3. The default is 10,000, the min value is 1, and
    the max value is 10,000,000. This message can be sent at any time after
    the engine has been created.

Message String: SET_EPOLL_TIMEOUT
Param 3:        unsigned long cast to a int
Param 4:        NULL
Description:
    This message is used to set the timeout in milli seconds used for
    epoll_wait() when event driven polling mode is enabled. The value should be
    passed in as Param 3. The default is 1,000, the min value is 1, and the max
    value is 10,000. This message can be sent at any time after the engine has
    been created. This message is not supported in the FreeBSD operating system
    or in the qatlib RPM.

Message String: ENABLE_EVENT_DRIVEN_POLLING_MODE
Param 3:        0
Param 4:        NULL
Description:
    This message changes the engines mode to use the Intel(R) QAT Drivers
    event driven polling feature. It must be sent if required after engine
    creation but before engine initialization.  It should not be sent after
    engine initialization. This message is not supported in the FreeBSD
    operating system or in the qatlib RPM.

Message String: DISABLE_EVENT_DRIVEN_POLLING_MODE
Param 3:        0
Param 4:        NULL
Description:
    This message changes the engines mode to use the timer based polling
    feature. It must be sent if required after engine creation but before
    engine initialization. It should not be sent after engine initialization.
    This message is not supported in the FreeBSD operating system or in the
    qatlib RPM.

Message String: GET_NUM_CRYPTO_INSTANCES
Param 3:        0
Param 4:        pointer to an int
Description:
    This message is used to retrieve the total number of crypto instances
    available as specified in the Intel(R) QAT Driver config file. The number
    of instances is assigned to the dereferenced int that is passed in as Param
    4. This message is used in conjunction with the GET_POLLING_FD message as in
    event driven polling mode with external polling there is an fd to listen to
    events on for each crypto instance. This message must be sent if required
    after the engine has been initialized.

Message String: GET_EXTERNAL_POLLING_FD
Param 3:        int cast to a long
Param 4:        pointer to an int
Description:
    This message is used to retrieve the file descriptor that can be used for
    event notification when the Intel(R) QAT Driver has had the event driven
    polling feature enabled. The value passed in as Param 3 is the instance to
    retrieve the fd for. The fd is returned by assigning to the dereferenced
    int passed as Param4. When retrieving fd's it is usual to first request how
    many instances there are with the GET_NUM_CRYPTO_INSTANCES message and then
    use a for loop to iterate through the instances starting from 0 and use
    this message to retrieve the fd for each instance. This message must be
    sent if required after the engine has been initialized. This message is
    not supported in the FreeBSD operating system or in the qatlib RPM.

Message String: SET_INSTANCE_FOR_THREAD
Param 3:        long
Param 4:        NULL
Description:
    This message is used to bind the thread to a specific instance number.
    Param 3 contains the instance number to bind to. If required, the message
    must be sent after the engine creation and will automatically trigger the
    engine initialization.

Message String: GET_NUM_OP_RETRIES
Param 3:        0
Param 4:        pointer to an unsigned int
Description:
    This message returns the number of retry operations.  The number is set in
    the variable passed in as Param 4.  This message may be sent at any time
    after engine initialization.

Message String: SET_MAX_RETRY_COUNT
Param 3:        int cast to a long
Param 4:        NULL
Description:
    This message is used for synchronous operations to determine how many times
    the engine should retry a message before flagging a failure. The value
    should be passed in as Param 3. Setting the value to -1 results in infinite
    retries. The default is 5 and the max value is 100,000. This message can be
    sent at any time after the engine is created.

Message String: SET_CRYPTO_SMALL_PACKET_OFFLOAD_THRESHOLD
Param 3:        0
Param 4:        NULL terminated string of cipher algorithm name and threshold
                value. Maximum length is 1024 bytes including NULL terminator.
Description:
    This message is used to set the threshold that determines the size crypto
    packets need to be before they are accelerated to the acceleration device.
    It is not efficient to accelerate very small packets to the accelerator as to
    do so would take longer to transfer the data to and from the accelerator
    than to encrypt/decrypt using the main CPU. The threshold value can be set
    independently for each EVP_CIPHER operation supported by the engine using
    the following names:
        AES-128-CBC-HMAC-SHA1
        AES-256-CBC-HMAC-SHA1
        AES-128-CBC-HMAC-SHA256
        AES-256-CBC-HMAC-SHA256
    The input format should be a string like this in one line:
        AES-128-CBC-HMAC-SHA1:4096,AES-256-CBC-HMAC-SHA1:8192
    Using a separator ":" between cipher name and threshold value.
    Using a separator "," between different cipher configurations.
    The default threshold value is 2048 bytes, the minimum is 0 bytes and the
    maximum is 16,384.
    The threshold value includes all the bytes that make up the TLS record
    including Record Header (5 bytes), IV (16 bytes), Payload, HMAC (20/32
    bytes), Padding (variable but could be max 255 bytes), and Padding Length
    (1 byte).
    The string should be NULL terminated and not more than 1024 bytes long
    including NULL terminator.
    This message is not supported when the engine is compiled with the flag
    --enable-qat_small_pkt_offload.

Message String: ENABLE_INLINE_POLLING
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable the inline polling mode of operation where
    a busy loop is used by the Intel(R) QAT OpenSSL* Engine to check for
    messages from the hardware accelerator after requests are sent to it.
    Currently this mode is only available in the synchronous RSA computation.
    It has no parameters or return value. If required this message must be sent
    after engine creation and before engine initialization.

Message String: ENABLE_HEURISTIC_POLLING
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable the heuristic polling mode of operation where
    the application can use the GET_NUM_REQUESTS_IN_FLIGHT message below to
    retrieve the number of different kinds of in-flight requests and
    intelligently determine the proper moment to perform the polling operation.
    This mode can be regarded as an improvement of the timer-based external
    polling. The external polling mode must be enabled first before enabling
    this mode. If required this message must be sent after engine creation and
    before engine initialization.

Message String: GET_NUM_REQUESTS_IN_FLIGHT
Param 3:        int cast to a long
Param 4:        pointer to an int address
Description:
    This message is used when heuristic polling is enabled to retrieve the
    number of different kinds of in-flight requests.
    The value passed in as param 3 is the indicator for a specific kind of
    request:
        #define GET_NUM_ASYM_REQUESTS_IN_FLIGHT 1
        #define GET_NUM_KDF_REQUESTS_IN_FLIGHT 2
        #define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT 3
    The first (i.e, value 1) is used to retrieve the number of asymmetric-key
    in-flight requests. The second (i.e, value 2) is used to retrieve the number
    of KDF(PRF and HKDF) in-flight requests.  The last (i.e, value 3) is used to
    retrieve the number of cipher in-flight requests (when the OpenSSL* pipelining
    feature is not used), or the number of in-flight pipelines (when the OpenSSL*
    pipelining feature is used).
    The address of the variable recording the specified info is returned by
    assigning to the dereferenced int address passed as Param 4. This means the
    application can directly use this int address to retrieve the specified info
    afterwards without sending this message again.
    This message may be sent at any time after engine initialization.

Message String: SET_CONFIGURATION_SECTION_NAME
Param 3:        0
Param 4:        NULL terminated string of section name from Intel(R) QAT Driver
                config file. Maximum length is 64 bytes including
                NULL terminator.
Description:
    This message is used to configure the Intel(R) QAT OpenSSL* Engine to use
    the string passed in as parameter 4 to be the name for the Intel(R) QAT
    Driver config section rather than the default `[SHIM]`. It must be sent
    after engine creation but before engine initialization. It should not be
    sent after engine initialization.

Message String: ENABLE_SW_FALLBACK
Param 3:        0
Param 4:        NULL
Description:
    This message is used to enable fallback to software (on-core) of the crypto
    operations normally accelerated to the acceleration devices by the
    Intel&reg; QuickAssist Technology OpenSSL\* Engine.  This command enables
    the software fallback feature - crypto operations will continue to be
    accelerated but, with this feature enabled, in the event the acceleration
    devices subsequently go offline the Intel&reg; QuickAssist Technology
    OpenSSL\* Engine will automatically switch to performing crypto operations
    on-core. If required this message must be sent after engine creation and
    before engine initialization. This message is not supported in the FreeBSD
    operating system or in the qatlib RPM.

Message String: HEARTBEAT_POLL
Param 3:        0
Param 4:        pointer to an int
Description:
    This message is used to check the acceleration devices are still functioning.
    It is normally used in conjunction with the Software Fallback feature
    (see engine command ENABLE_SW_FALLBACK) when using External Polling Mode
    (see engine command ENABLE_EXTERNAL_POLLING). The result of this
    engine specific message (success/failure) is assigned to the dereferenced int
    that is passed in as Param 4.
    Polling using this message will result in the Intel&reg; QuickAssist Technology
    OpenSSL\* Engine being notified when instances of an acceleration device go
    offline or come back online. By sending this message more frequently you can
    decrease the time taken for the engine to become aware of instances going
    offline/coming back online at the expense of additional cpu cycles. The
    suggested polling interval would be around 0.5 seconds to 1 second. This
    message may be sent at any time after engine initialization. This message
    is not supported in the FreeBSD operating system or in the qatlib RPM.

Message String: DISABLE_QAT_OFFLOAD
Param 3:        0
Param 4:        NULL
Description:
    This message is used to disable acceleration of crypto operations to the
    acceleration devices when QAT HW Acceleration is enabled, with the immediate
    effect that these operations are performed on-core instead.
    This message may be sent at any time after engine initialization.

Message String: HW_ALGO_BITMAP
Param 3:        0
Param 4:        pointer to an unsigned long int
Description:
    This message is used to set the global QAT_HW algorithm bitmap and will
    trigger the bind_qat() again to reload the QAT_HW algorithm method according
    to the input bitmap value. The input value should be a hex string, like
    0x82EF, which is the combination of the bitmap for each algorithm. Currently,
    the Engine supports the first 16 bits of the input value, the higher bit value
    will be deprecated. The default QAT_HW algorithm bitmap is 0xFFFF which means
    all algorithms are supported at the runtime level.
    For more detailed usage, refer to: docs/qat_common.md

Message String: SW_ALGO_BITMAP
Param 3:        0
Param 4:        pointer to an unsigned long int
Description:
    This message is used to set the global QAT_SW algorithm bitmap and will
    trigger the bind_qat() again to reload the QAT_SW algorithm method according
    to the input bitmap value. The input value should be a hex string, like
    0x82EF, which is the combination of the bitmap for each algorithm. Currently,
    the Engine supports the first 16 bits of the input value, the higher bits value
    will be deprecated. The default QAT_SW algorithm bitmap is 0xFFFF which means
    all algorithms are supported at the runtime level.
    For more detailed usage, refer to: docs/qat_common.md

```
