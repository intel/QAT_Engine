# Intel&reg; QuickAssist Technology(QAT) OpenSSL\* Engine

## Licensing

The Licensing of the files within this project is split as follows:

Intel&reg; Quickassist Technology(QAT) OpenSSL\* Engine - BSD License.
Please see the `LICENSE` file contained in the top level folder.

Example Intel&reg; Contiguous Memory Driver contained within the folder
`qat_contig_mem` - Dual BSD/GPLv2 License. Please see the file headers
within the `qat_contig_mem` folder and the full GPLv2 license contained
in the file `LICENSE.GPL` within the `qat_contig_mem` folder.

Example Intel&reg; Quickassist Technology Driver Configuration Files
contained within the folder hierarchy `qat` - Dual BSD/GPLv2 License.
Please see the file  headers of the configuration files and the full
GPLv2 license contained in the file `LICENSE.GPL` within the `qat` folder.

## Features

* Synchronous and Asynchronous Operation
* Asymmetric PKE Offload
  * RSA Support with PKCS1 Padding for Key Sizes 1024/2048/4096.
  * DH Support for Key Sizes 768/1024/1536/2048/3072/4096.
  * DSA Support for Key Sizes 160/1024, 224/2048, 256/2048, 256/3072.
  * ECDH Support for the following curves:
    * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
    * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
    * NIST Koblitz Curves: K-163/K-233/K-283/K409/K-571.
  * ECDSA Support for the following curves:
    * NIST Prime Curves: P-192/P-224/P-256/P-384/P-521.
    * NIST Binary Curves: B-163/B-233/B-283/B-409/B-571.
    * NIST Koblitz Curves: K-163/K-233/K-283/K409/K-571.
* Symmetric Chained Cipher Offload:
  * AES128-CBC-HMAC-SHA1/AES256-CBC-HMAC-SHA1.
  * AES128-CBC-HMAC-SHA256/AES256-CBC-HMAC-SHA256.
* Pseudo Random Function (PRF) offload.

## Hardware Requirements

This OpenSSL\* Engine supports crypto offload to the following acceleration
devices:

* Intel&reg; Communications Chipset 8900 to 8920 Series
* Intel&reg; Communications Chipset 8925 to 8955 Series
* Intel&reg; Atom&trade; Processor C2000

## Software Requirements

Successful operation of this release requires a software tool chain that
supports OpenSSL\* 1.1.0.
This release was validated on the following:

* Operating system: Fedora* 16 64-bit version
* Kernel: GNU\*/Linux\* 3.1.0.7
* Intel&reg; Communications Chipset 895x Series Software for Linux\*, version 2.6
* OpenSSL\* 1.1.0 tag OpenSSL_1_1_0

## Limitations

CAUTION: Please note that the software provided in this release is
"sample software" that is not fully functional or fully tested and
is known to contain bugs and errors. As such, Intel&reg; does not
recommend the use of the software in its current state for your
production use.

* When forking within an application it is not valid for
  a cryptographic operation to be started in the parent process
  and completed in the child process.
* Only one level of forking is permitted, if a child process forks
  again then the Intel&reg; Quickassist Technology OpenSSL\* Engine will
  not be available in that forked process.

## Installation Instructions

### Build Intel&reg; QuickAssist Technology Driver

Please follow the instructions contained in:

Intel&reg; Communications Chipset 89xx Series Software for Linux\* - Getting
Started Guide (330750)

or in

Intel&reg; Atom&trade; Processor C2000 Product Family for Communications
Infrastructure Software - Getting Started Guide (333035)

These instructions can be found on the 01.org website in the following
section:

<https://01.org/packet-processing/intel%C2%AE-quickassist-technology-drivers-and-patches>

### Build OpenSSL\*

Clone OpenSSL\* from Github\* at the following location:

    git clone https://github.com/openssl/openssl.git

It is recommended to checkout and build against OpenSSL\* 1.1.0 tag
OpenSSL_1_1_0.
Older versions of OpenSSL\* are not supported.

Due to the nature of the Intel&reg; QuickAssist Technology OpenSSL\*
Engine being a dynamic engine it can only be used with shared library
builds of OpenSSL\*.

Note: The OpenSSL\* 1.1.0 baseline builds as a shared library by default
now so there is no longer any need to specify the `shared` option when
running `./config`.

Note: It is not recommended to install the accelerated version of
OpenSSL\* as your default system library. If you do you may find that
acceleration is used unexpectedly by other applications on the system
resulting in undesired/unsupported behaviour. The `--prefix` can be used
with the `./config` command to specify the location that make install will
copy files to. Please see the OpenSSL\* INSTALL file for full details on
usage of the `--prefix` option.

An example build would be:
```bash
    cd /path/to/openssl
    ./config --prefix=/path/to/openssl_install
    make depend (if recommended by the OpenSSL* build system)
    make
    make install
```
As the Intel&reg; Quickassist Technology OpenSSL\* Engine will be built
as a dynamic engine it is important to
tell OpenSSL\* where to find the dynamic engines at runtime. This is
achieved by exporting the following environment variable:

    export OPENSSL_ENGINES=/path/to/openssl_install/lib/engines-1.1

Note: This variable will need to be present in the environment whenever
the engine is used.

### Build the Intel&reg; Quickassist Technology OpenSSL\* Engine

Clone the Github\* repository containing the Intel&reg; Quickassist
Technology OpenSSL\* Engine:

    git clone https://github.com/01org/QAT_Engine.git

The repository can be cloned to either a subdirectory within the OpenSSL\*
repository, for instance `/path/to/openssl/engines` or to its own unique
location on the file system, for instance `/path/to/qat_engine`.
In either case the engine will not be built as part of the OpenSSL\* build
and will require building manually.

The following example is assuming the engine was cloned into:
`/path/to/qat_engine`.

To build the engine:

```bash
    cd /path/to/qat_engine
   ./configure \
    --with-qat_dir=/path/to/qat_driver \
    --with-qat_install_dir=/path/to/qat_driver/build \
    --with-openssl_dir=/path/to/openssl \
    --with-openssl_install_dir=/path/to/openssl_install
    make depend
    make
    make install
```

In the above example this will create the file `qat.so` in
`/path/to/qat_engine` and copy it to
`/path/to/openssl_install/lib/engines-1.1`.

Note: When building it is possible to specify command line options
that can be used to turn engine functionality on and off. Please see
the Intel&reg; Quickassist Technology OpenSSL\* Engine Build Options section
below for a full description of the options that can be specified.
The above options are all mandatory.

If building to link against the Upstream Intel&reg; Quickassist
Technology userspace shared library then ensure the ./configure
command was also run with the --with-upstream_driver_cmd_dir option as
this is mandatory for building with the upstream version of the library.

### Copy the correct Intel&reg; Quickassist Technology Driver config files

The Intel&reg; Quickassist Technology OpenSSL\* Engine comes with some example
conf files to use with the Intel Quickassist Technology Driver.
The Intel&reg; Quickassist Technology OpenSSL\* Engine will not function with
the default Intel&reg; Quickassist Technology Driver conf file
because the default conf does not contain a `[SHIM]` section which the
Intel&reg; Quickassist Technology OpenSSL\* Engine requires. The conf files are
located at:

`/path/to/qat_engine/qat/config`

The files are grouped by acceleration device, please choose the files
appropriate to your acceleration device only.
If building to link against the Upstream Intel&reg; Quickassist
Technology userspace shared library then you should use the files in
`dh895xcc_upstream`

The files are also split into `multi_process_optimized` and
`multi_thread_optimized`.

If your application runs one (or very few) processes,
but has multiple threads in each process, each accessing the acceleration
device, then you should pick the `multi_thread_optimized` config files. An
example of this is a webserver that creates a new thread for each incoming
connection.

If your application scales by creating new processes, then you should pick
the `multi_process_optimized` config files. An example of this is an
event driven application that runs as a single thread in an event loop.
In this type of application it is usual for the application to create
at least one new process for each cpu core you want to utilize.

There are also similar config files for if you are using the event
driven polling feature of the Intel&reg; Quickassist Technology Driver.
Once you have decided which conf file you should use, or created your
own you should follow the procedure below to install it:

1. Follow the instructions in the:
   Intel&reg; Communications Chipset 89xx Series Software for Linux\* - Getting
   Started Guide (330750) - Section 3.4 Starting/Stopping the Acceleration
   Software.
   or
   Intel&reg; Atom&trade; Processor C2000 Product Family for Communications
   Infrastructure Software - Getting Started Guide (333035) - Section 9.5
   Starting/Stopping the Acceleration Software.
   to stop the Acceleration Software.
2. Copy the appropriate `.conf` file to `/etc`
3. Follow the instructions in the:
   Intel&reg; Communications Chipset 89xx Series Software for Linux\* - Getting
   Started Guide (330750) - Section 3.4 Starting/Stopping the Acceleration
   Software.
   or
   Intel&reg; Atom&trade; Processor C2000 Product Family for Communications
   Infrastructure Software - Getting Started Guide (333035) - Section 9.5
   Starting/Stopping the Acceleration Software.
   to start the Acceleration Software.

### Build and install the contiguous memory driver

The Intel&reg; QuickAssist Technology API requires many of the data
structures (those that will be passed to the hardware) to be allocated
in contiguous pinned memory in order to support DMA operations.
The Intel&reg; QuickAssist Technology OpenSSL\* Engine comes with an
example kernel space contiguous memory driver that can be used to try
out operation of the engine. It is considered to be an example only
and is not written to be a production quality driver.

To build/install the qat\_contig\_mem driver follow these steps:

```bash
    cd /path/to/qat_engine/qat_contig_mem
    make
    make load
    make test
```

The expected output from `make test` should be something similar
to the following:

    seg mapped to 0x7f9eedd6e000, virtualAddress in seg 0xffff880ac9c0c000,
    length 64
    Hello world!
    # PASS Verify for QAT Contig Mem Test

### Test the Intel&reg; Quickassist Technology OpenSSL\* Engine

Run this command to check if the Intel&reg; Quickassist Technology OpenSSL\*
Engine is loaded correctly:

```text
    cd /path/to/openssl/apps
    ./openssl engine -t -c -vvvv qat
    (qat) Reference implementation of QAT crypto engine
     [RSA, DSA, DH, AES-128-CBC-HMAC-SHA1, AES-256-CBC-HMAC-SHA1,
      AES-128-CBC-HMAC-SHA256, AES-256-CBC-HMAC-SHA256 TLS1-PRF]
         [ available ]
         ENABLE_POLLING: Enables the polling interface to the engine.
              (input flags): NO_INPUT
         POLL: Polls the engine for any completed requests
              (input flags): NO_INPUT
         SET_INSTANCE_FOR_THREAD: Set instance to be used by this thread
              (input flags): NUMERIC
         GET_OP_RETRIES: Get number of retries
              (input flags): NO_INPUT
         SET_MSG_RETRY_COUNT: Set Message retry count
              (input flags): NUMERIC
         SET_POLL_INTERVAL: Set Poll Interval
              (input flags): NUMERIC
         GET_POLLING_FD: Returns non blocking fd for crypto engine
              (input flags): NO_INPUT
         ENABLE_EVENT_DRIVEN_MODE: Set event driven mode
              (input flags): NO_INPUT
         GET_NUM_CRYPTO_INSTANCES: Get the number of crypto instances
              (input flags): NO_INPUT
         DISABLE_EVENT_DRIVEN_MODE: Set event driven mode to off
              (input flags): NO_INPUT
```


### Run speed with Intel&reg; Quickassist Technology OpenSSL\* Engine

```text
    cd /path/to/openssl/apps

    * RSA 2K
      * Asynchronous
      ./openssl speed -engine qat -elapsed -async_jobs 72 rsa2048
      * Synchronous
      ./openssl speed -engine qat -elapsed rsa2048
      * Software
      ./openssl speed -elapsed rsa2048
    * ECDH Compute Key
      * Asynchronous
      ./openssl speed -engine qat -elapsed -async_jobs 36 ecdh
      * Synchronous
      ./openssl speed -engine qat -elapsed ecdh
      * Software
      ./openssl speed -elapsed ecdh
    * Chained Cipher: aes-128-cbc-hmac-sha1
      * Asynchronous
      ./openssl speed -engine qat -elapsed -async_jobs 128 -multi 2 -evp aes-128-cbc-hmac-sha1
      * Synchronous
      ./openssl speed -engine qat -elapsed -multi 2 -evp aes-128-cbc-hmac-sha1
      * Software
      ./openssl speed -elapsed -multi 2 -evp aes-128-cbc-hmac-sha1
```

## Troubleshooting

The most likely failure point is that the Intel&reg; Quickassist Technology
OpenSSL\* Engine is not loading successfully.
If this occurs some of the things to check are:

   1. Has the qat\_contig\_mem driver been loaded successfully? If not the
      engine will fail to initialise. Check by running `lsmod`, qat\_contig\_mem
      should be in the list.
   2. Has the correct Intel&reg; Quickassist Technology Driver config file
      been copied to `/etc`? Check it has a `[SHIM]` section and that the
      Intel&reg; Quickassist Technology Driver software was restarted
      so that it picked up the new config file.
   3. Is the Intel&reg; Quickassist Technology Driver up and running?
      Check by running `lsmod`, icp_qa_al should be in the list.
      Also check the Intel&reg; Quickassist Technology Driver software
      has been started.
   4. Were the paths set correctly so the `qat.so` engine file
      was copied to the correct location?
      Check they really are there.
   5. Has the environment variable `OPENSSL_ENGINES` been correctly
      defined and exported to the shell?
      Also check it is really pointing to the correct location.

If running on a Debian\* based OS (Ubuntu\* for example) it is
possible that the Intel&reg; Quickassist Technology Driver userspace
shared library needed by the Intel&reg; Quickassist Technology
OpenSSL\* Engine may not be located even though it has been
installed. To resolve this it is recommended to add the /lib64
folder to the LD_LIBRARY_PATH environment variable as follows:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/lib64

If building to link against the Upstream Intel&reg; Quickassist
Technology userspace shared library then ensure the ./configure
command was run with the --with-upstream_driver_cmd_dir option as
this is mandatory for building with the upstream version of the library.

## Intel&reg; Quickassist Technology OpenSSL\* Engine Specific Messages

OpenSSL\* engines support a mechanism whereby custom messages can be
defined for an application to communicate directly with the engine.
These messages are typically used in two ways:

   1. Firstly in order to set configuration options. These messages
      are typically sent before the engine is initialized. Sending
      these after initialization will typically have no effect.
   2. Secondly in order to control the engine operation. These
      messages may be sent before initialization or after or both.

The custom message mechanism passes a string to identify the
message and uses a number of parameters to pass information into
or out of the engine. It is defined as follows:

```
    ENGINE_ctrl_cmd(<Engine>, <Message String>, <Param 3>,
                    <Param 4>, NULL, 0\)
```

Where:

   - &lt;Engine&gt; is a pointer to the Intel&reg; QuickAssist Technology enabled
     OpenSSL\* Engine.
   - &lt;Message String&gt; is a string representing the message type.
   - &lt;Param 3&gt; is long that can be used to pass a number or a
     pointer can be cast to it.
   - &lt;Param 4&gt; is a void pointer used to pass data structures in.
   - The last 2 parameters are always NULL and 0 when used with
     the Intel&reg; Quickassist Technology OpenSSL\* Engine.

```text
    Message String: ENABLE_POLLING
    Param 3:        0
    Param 4:        NULL
    Description:
        This message is used to enable the external polling mode
        of operation where it becomes the applications
        responsibility to use the POLL message below to check
        for messages that have been returned from the hardware
        accelerator. It has no parameters or return value.
        If required this message must be sent between
        engine creation and engine initialization.

    Message String: POLL
    Param 3:        0
    Param 4:        pointer to an int
    Description:
        This message is used when external polling is enabled to
        request poll of all instances. The status of the request
        is passed back in the variable passed in as Param 4. This
        message may be sent at any time after engine initialization.

    Message String: SET_INSTANCES_FOR_THREAD
    Param 3:        long
    Param 4:        NULL
    Description:
        This message is used to bind the thread to a specific
        instance number. Param 3 contains the instance number
        to bind to. If required the message must be sent
        between engine creation and engine initialization.

    Message String: GET_OP_RETRIES
    Param 3:        0
    Param 4:        pointer to an unsigned int
    Description:
        This message returns the number of retry operations.
        The number is set in the variable passed in as Param 4.
        This message may be sent at any time after engine
        initialization.

    Message String: SET_MSG_RETRY_COUNT
    Param 3:        int cast to a long
    Param 4:        NULL
    Description:
        This message is used for synchronous operations to
        determine how many times the engine should retry a
        message before flagging a failure. The value should
        be passed in as Param 3. Setting the value to -1
        results in infinite retries. The default is 5 and
        the max value is 100,000. This message can be sent
        at any time after the engine is created.

    Message String: SET_POLL_INTERVAL
    Param 3:        unsigned long cast to a long
    Param 4:        NULL
    Description:
        This message is used to set the interval in nano
        seconds between polling for messages coming back
        from the hardware accelerator. The value should
        be passed in as Param 3. The default is 10,000,
        the min value is 1, and the max value is
        10,000,000. This message can be sent at any time
        after the engine has been created.

    Message String: ENABLE_EVENT_DRIVEN_MODE
    Param 3:        0
    Param 4:        NULL
    Description:
        This message changes the engines mode to use the
        Intel&reg; Quickassist Technology Drivers event
        driven polling feature. It must be sent if required
        after engine creation but before engine initialization.
        It should not be sent after engine initialization.

    Message String: DISABLE_EVENT_DRIVEN_MODE
    Param 3:        0
    Param 4:        NULL
    Description:
        This message changes the engines mode to use the
        timer based polling feature.
        It must be sent if required after engine creation
        but before engine initialization. It should not
        be sent after engine initialization.

    Message String: GET_NUM_CRYPTO_INSTANCES
    Param 3:        0
    Param 4:        pointer to an int
    Description:
        This message is used to retrieve the total
        number of crypto instances available as
        specified in the Intel&reg; Quickassist Technology
        Driver config file. The number of instances is assigned
        to the dereferenced int that is passed in as Param 4.
        This message is used in conjunction with the
        GET_POLLING_FD message as in event driven
        polling mode with external polling there
        is an fd to listen to events on for each
        crypto instance. This message must be
        sent if required after the engine has been
        initialized.

    Message String: GET_POLLING_FD
    Param 3:        int cast to a long
    Param 4:        pointer to an int
    Description:
        This message is used to retrieve the file descriptor
        that can be used for event notification when the
        Intel&reg; Quickassist Technology Driver has had the event
        driven polling feature enabled. The value passed in as
        Param 3 is the instance to retrieve the fd for. The fd is
        returned by assigning to the dereferenced int passed as
        Param4. When retrieving fd's it is usual to first request
        how many instances there are with the
        GET_NUM_CRYPTO_INSTANCES message and then use a for
        loop to iterate through the instances starting from 0
        and use this message to retrieve the fd for each
        instance. This message must be sent if required
        after the engine has been initialized.
```

## Intel&reg; Quickassist Technology OpenSSL\* Engine Build Options

The following is a list of the options that can be used with the
`./configure` command when building the Intel&reg; Quickassist Technology
OpenSSL\* Engine:

```
    Mandatory

    --with-qat_dir=/path/to/qat_driver
        Specify the path to the source code of the Intel&reg; Quickassist
        Technology Driver. If you do not specify this the build will fail.

    --with-qat_install_dir=/path/to/qat_driver/build
        Specify the path to the location of the Intel&reg; Quickassist
        Technology Driver library files. If you do not specify this the
        link will fail.

    --with-openssl_dir=/path/to/openssl
        Specify the path to the top level of the OpenSSL\* source code.
        If you do not specify this the build will fail.

    --with-openssl_install_dir=/path/to/openssl_install
        Specify the path to the top level where the OpenSSL\* build was
        installed to. This is needed so that the qat.so engine library
        can be copied into the folder containing the other dynamic engines
        when you run 'make install'. If you do not specify this then
        'make install' will fail.

    Optional

    --with-cmd_dir=/path/to/common_memory_driver
        Specify the path to the top level folder containing the Common
        Memory Driver. The Common Memory Driver is an alternative pinned
        contiguous memory driver that is distributed with the Intel&reg;
        Quickassist Technology Driver. It can be used instead of the
        supplied qat_contig_mem memory driver. Specifying this parameter
        will cause the engine to be built to use the Common Memory Driver
        rather than the default qat_contig_mem driver.

    --with-upstream_driver_cmd_dir=/path/to/common_memory_driver
        Specify the path to the top level folder containing the Common
        Memory Driver. The Upstream Intel&req; Quickassist Technology
        Driver uses the Common Memory Driver by default but requires
        the Common Memory Driver shared userspace library to be linked into
        the engine. Specifying this option tells the linker that the engine
        is being linked against the Upstream Intel&reg; Quickassist
        Technology Driver and the path to the needed Common Memory Driver
        library. Specifying this path does not mean the engine will use the
        Common Memory Driver for its internal contiguous pinned memory
        allocations. If that is also required then the --with-cmd_dir
        option should also be specified pointing to the same location.
        If you are building on a system with the Upstream Intel&reg;
        Quickassist Technology Driver then it is Mandatory to specify this
        option.

    --disable-qat_rsa/--enable-qat_rsa
        Disable/Enable Intel&reg; Quickassist Technology
        RSA offload (enabled by default)

    --disable-qat_dsa/--enable-qat_dsa
        Disable/Enable Intel&reg; Quickassist Technology
        DSA offload (enabled by default)

    --disable-qat_dh/--enable-qat_dh
        Disable/Enable Intel&reg; Quickassist Technology
        DH offload (enabled by default)

    --disable-qat_ecdh/--enable-qat_ecdh
        Disable/Enable Intel&reg; Quickassist Technology
        ECDH offload (enabled by default)

    --disable-qat_ecdsa/--enable-qat_ecdsa
        Disable/Enable Intel&reg; Quickassist Technology
        ECDSA offload (enabled by default)

    --disable-qat_ciphers/--enable-qat_ciphers
        Disable/Enable Intel&reg; Quickassist Technology
        Chained Cipher offload (enabled by default)

    --disable-qat_prf/--enable-qat_prf
        Disable/Enable Intel&reg; Quickassist Technology
        PRF offload (enabled by default)

    --disable-qat_debug/--enable-qat_debug
        Disable/Enable debug output to aid debugging. Warning: This
        option should never be enabled in a production environment as
        it may output private key information to the console/logs and
        may also introduce side channel timing attack
        vulnerabilities (disabled by default).

    --disable-qat_warnings/--enable-qat_warnings
        Disable/Enable warnings to aid debugging. Warning: This
        option should never be left on in a production environment
        as it may introduce side channel timing attack
        vulnerabilities (disabled by default).

    --disable-qat_mem_debug/--enable-qat_mem_debug
        Disable/Enable debug output from the userspace memory management
        code to aid debugging. This option produces quite verbose output
        hence why it is separate to the standard debug. Warning: This
        option should never be enabled in a production environment as
        it may output private key information to the console/logs and
        may also introduce side channel timing attack
        vulnerabilities (disabled by default).

    --disable-qat_mem_warnings/--enable-qat_mem_warnings
        Disable/Enable warnings from the userspace memory management code
        to aid debugging. Warning: This option should never be left on
        in a production environment as it may introduce side channel
        timing attack vulnerabilities (disabled by default).

    --disable-multi_thread/--enable-multi_thread
        Disable/Enable an alternative way of managing within userspace the
        pinned contiguous memory allocated by the qat_contig_mem
        driver. This alternative method will give improved performance
        in a multi-threaded environment by making the slab pools
        thread local to avoid locking between threads. Although this
        can give better performance there are several drawbacks such
        as the memory slabs will be utilized less efficiently, and you
        cannot allocate in one thread and free in another thread.
        Running in this mode also does not support processes that
        fork (disabled by default).

    --disable-qat_mux/--enable-qat_mux
        Disable/Enable support for building using the Mux mode of the
        Intel&reg; Quickassist Technology Driver. Mux mode allows you to
        mix Intel&reg; Communications Chipset 8900 to 8920 Series hardware
        and Intel&reg; Communications Chipset 8925 to 8955 Series hardware
        within the same system using a common driver interface. You
        should only specify this option if using a mixture of hardware
        (disabled by default).

    --with-cc-opt="parameters"
        Sets additional parameters that will be added to the CFLAGS
        variable at compile time.

    --with-ld-opt="parameters"
        Sets additional parameters that will be used during linking.
```

## Legal

Intel, and Intel Atom are trademarks of
Intel Corporation in the U.S. and/or other countries.

\*Other names and brands may be claimed as the property of others.

Copyright &copy; 2016, Intel Corporation. All rights reserved.
