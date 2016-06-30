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
contained within the folder heirarchy `qat` - Dual BSD/GPLv2 License.
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
* Intel&reg; Communications Chipset 895x Series Software for Linux\*, version 2.5
* OpenSSL\* 1.1.0 tag OpenSSL_1_1_0-pre5

## Limitations

CAUTION: Please note that the software provided in this release is
"sample software" that is not fully functional or fully tested and
is known to contain bugs and errors. As such, Intel&reg; does not
recommend the use of the software in its current state for your
production use. 

* Zero Copy Mode is not supported in this release.
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
OpenSSL_1_1_0-pre5.
Older versions of OpenSSL\* are not supported.

Due to the nature of the Intel&reg; QuickAssist Technonlogy OpenSSL\*
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

    export OPENSSL_ENGINES=/path/to/openssl_install/lib/engines

Note: This variable will need to be present in the environment whenever
the engine is used.

### Build the Intel&reg; Quickassist Technology OpenSSL\* Engine

Clone the Github\* repository containing the Intel&reg; Quickassist
Technology OpenSSL\* Engine:

    git clone https://github.com/01org/QAT_Engine.git

The repository can be cloned to either a subdirectory within the openssl
repository, for instance `/path/to/openssl/engines` or to its own unique
location on the file system, for instance `/path/to/qat_engine`.
In either case the engine will not be built as part of the OpenSSL\* build
and will require building manually.

The following example is assuming the engine was cloned into:
`/path/to/qat_engine`.

Before building the engine there are some variables
that are mandatory to be exported to the environment:

* `ICP_ROOT` is the path to the top level of the Intel&reg;
  Quickassist Technology Driver
  source tree.
* `OPENSSL_ENGINES` is the path to where OpenSSL\* engines are
  placed when `make install` is run on the OpenSSL\* baseline. If
  you have just built  OpenSSL* following the steps in the section 
  above then you should have already exported this variable.

For example you may set them as follows:

    export ICP_ROOT=/path/to/qat_driver
    export OPENSSL_ENGINES=/path/to/openssl_install/lib/engines

The following variables are not mandatory but are needed if they need
to be different from the default:

* `ICP_BUILD_OUTPUT` default is `$ICP_ROOT/build`. `ICP_BUILD_OUTPUT`
  is the directory the Intel&reg; Quickassist Technology Driver build
  output is placed in.  
* `OPENSSL_ROOT` default is `../..` relative to the directory you are
  building in. `OPENSSL_ROOT` is the path to the top level of the
  OpenSSL* source tree.

For example you may set them as follows:

    export ICP_BUILD_OUTPUT=/path/to/qat_driver/build
    export OPENSSL_ROOT=/path/to/openssl

The following variable is not mandatory but is needed if building 
against the upstream driver:

* `UPSTREAM_DRIVER_CMN_ROOT` is the path to the Intel&reg; Quickassist 
  Technology Driver user space memory driver shared library `libqae_mem_s.so`.

For example you may set it as follows:

    export UPSTREAM_DRIVER_CMN_ROOT=/path/to/qat_driver/
                                    quickassist/utilities/libqae_mem

To build the engine:

```bash
    cd /path/to/qat_engine
    make
    make install
```

In the above example this will create the file `qat.so` in 
`/path/to/qat_engine` and copy it to
`/path/to/openssl_install/lib/engines`.
It will also create the file `libqae_mem_utils.so` in 
`/path/to/qat_engine` and copy it to
`/path/to/openssl_install/lib`.

Note: When building it is possible to specify build flags
that can be used to turn engine functionality on and off. Please see
the Intel&reg; Quickassist Technology OpenSSL\* Engine Build Flags section
below for a full description of the options that can be specified. Build
flags can be specified by exporting the following variable into the
environment:

    export QAT_FLAGS=<flags>

or they can be specified directly on the `make` commandline.

Before you can run applications that use the qat engine it is
necessary for the system to know where the libqae_mem_utils.so
library is located. A suggested method for this is to add the
path to the `LD_LIBRARY_PATH` environment variable as follows:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/openssl_install/lib

This path needs to be in the `LD_LIBRARY_PATH` whenever the engine is
used.

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
    Hello World!

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
         SET_V2P: Set function to be used for V2P translation
              (input flags): NUMERIC
         ENABLE_ZERO_COPY_MODE: Set zero copy mode
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
   4. Were the paths set correctly so the `qat.so` engine file and
      `libqae_mem_utils.so` file were copied to the correct location?
      Check they really are there. 
   5. Have the environment variables `OPENSSL_ENGINES` and `LD_LIBRARY_PATH`
      been correctly defined and exported to the shell?
      Also check they really are pointing to the correct locations.

If running on a Debian\* based OS (Ubuntu\* for example) it is
possible that the Intel&reg; Quickassist Technology Driver userspace
shared library needed by the Intel&reg; Quickassist Technology
OpenSSL\* Engine may not be located even though it has been
installed. To resolve this it is recommended to add the /lib64
folder to the LD_LIBRARY_PATH environment variable as follows:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/lib64

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

    Message String: SET_V2P
    Param 3:        function pointer cast to a long
    Param 4:        NULL
    Description:
        This message sets the function that the engine and the
        Intel&reg; Quickassist Technology Driver will use for 
        converting virtual addresses to physical addresses for the
        pinned contiguous memory buffers. A function pointer to
        the appropriately signatured function should be
        cast to a long and passed as Param 3. This message
        is usually used in conjunction with the
        ENABLE_ZERO_COPY_MODE message to allow applications
        to manage memory allocations themselves. This message
        must be sent between engine creation and engine
        initialization and before sending
        ENABLE_ZERO_COPY_MODE.

    Message String: ENABLE_ZERO_COPY_MODE
    Param 3:        0
    Param 4:        NULL
    Description:
        This message sets zero copy mode within the engine.
        This reduces memory copies by assuming the
        application is responsible for ensuring buffers
        passed into the engine are contiguous pinned memory.
        This message must be sent between engine creation
        and engine initialization and should be called
        after a SET_V2P message.

    Message String: SET_MSG_RETRY_COUNT
    Param 3:        int cast to a long
    Param 4:        NULL
    Description:
        This messagee is used for synchronous operations to
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
        It should not be sent after engine intialization.

    Message String: DISABLE_EVENT_DRIVEN_MODE
    Param 3:        0
    Param 4:        NULL
    Description:
        This message changes the engines mode to use the
        timer based polling feature.
        It must be sent if required after engine creation
        but before engine initialization. It should not
        be sent after engine intialization.

    Message String: GET_NUM_CRYPTO_INSTANCES
    Param 3:        0
    Param 4:        pointer to an int
    Description:
        This message is used to retrieve the total
        number of crypto instances available as
        specified in the Intel&reg; Quickassist Technology
        Driver config file. The number of instances is assigned
        to the dereferenced int that is passed in as Param 4.
        This message is used in conjuction with the
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

## Intel&reg; Quickassist Technology OpenSSL\* Engine Build Flags

The following is a list of the compile flags that can be used when 
building the Intel&reg; Quickassist Technology OpenSSL\* Engine:

```
    -DOPENSSL_DISABLE_QAT_RSA/-DOPENSSL_ENABLE_QAT_RSA
        Disable/Enable Intel&reg; Quickassist Technology 
        RSA offload (enabled by default)
 
    -DOPENSSL_DISABLE_QAT_DSA/-DOPENSSL_ENABLE_QAT_DSA
        Disable/Enable Intel&reg; Quickassist Technology 
        DSA offload (enabled by default)

    -DOPENSSL_DISABLE_QAT_DH/-DOPENSSL_ENABLE_QAT_DH
        Disable/Enable Intel&reg; Quickassist Technology 
        DH offload (enabled by default)

    -DOPENSSL_DISABLE_QAT_ECDH/-DOPENSSL_ENABLE_QAT_ECDH
        Disable/Enable Intel&reg; Quickassist Technology 
        ECDH offload (enabled by default)

    -DOPENSSL_DISABLE_QAT_ECDSA/-DOPENSSL_ENABLE_QAT_ECDSA
        Disable/Enable Intel&reg; Quickassist Technology 
        ECDSA offload (enabled by default)

    -DOPENSSL_DISABLE_QAT_CIPHERS/-DOPENSSL_ENABLE_QAT_CIPHERS
        Disable/Enable Intel&reg; Quickassist Technology 
        Chained Cipher offload (enabled by default)

    -DOPENSSL_DISABLE_QAT_PRF/-DOPENSSL_ENABLE_QAT_PRF
        Disable/Enable Intel&reg; Quickassist Technology 
        PRF offload (enabled by default)

    -DQAT_DEBUG
        Enable debug output to aid debugging. Warning: This option
        should never be enabled in a production environment as it
        may output private key information to the console/logs and
        may also introduce side channel timing attack 
        vulnerabilities (disabled by default).

    -DQAT_WARN
        Enable warnings to aid debugging. Warning: This option
        should never be left on in a production environment
        as it may introduce side channel timing attack
        vulnerabilities (disabled by default).

    -DQAT_MEM_DEBUG
        Enable debug output from the userspace memory management code
        to aid debugging. This option produces quite verbose output hence
        why it is separate to the standard debug. Warning: This option
        should never be enabled in a production environment as it
        may output private key information to the console/logs and
        may also introduce side channel timing attack 
        vulnerabilities (disabled by default).

    -DQAT_MEM_WARN
        Enable warnings from the userspace memory management code
        to aid debugging. Warning: This option should never be left on
        in a production environment as it may introduce side channel
        timing attack vulnerabilities (disabled by default).
```

## Legal

Intel, and Intel Atom are trademarks of
Intel Corporation in the U.S. and/or other countries.

\*Other names and brands may be claimed as the property of others.

Copyright &copy; 2016, Intel Corporation. All rights reserved.
