# Troubleshooting

The most likely failure point is that the Intel&reg; QAT OpenSSL\* Engine is not
loading successfully.
If this occurs some of the things to check are:

   1. Has the USDM memory driver been loaded successfully? If not the engine
      will fail to initialise. Check by running `lsmod` for Linux and `kldstat`
      for FreeBSD, usdm_drv should be in the list. If using the alternative
      qat\_contig\_mem driver, look for qat\_contig\_mem. (qat_hw specific)
   2. Has the correct Intel&reg; QAT Driver config file been copied to `/etc`?
      Check it has a `[SHIM]` section and that the Intel&reg; QAT Driver
      software was restarted so that it picked up the new config file.
      (qat_hw specific)
   3. Is the Intel&reg; QAT Driver up and running?  Check by running `adf_ctl`,
      device details along with the state should be `state: up`.
      Also check the Intel&reg; QAT Driver software has been started.
      (qat_hw specific)
   4. Were the paths set correctly so that the `qatengine.so` engine file was
      copied to the correct location? Check they really are there.
   5. Has the environment variable `OPENSSL_ENGINES` been correctly defined and
      exported to the shell?
      Also check it is really pointing to the correct location.
   6. If building for OpenSSL 1.1.0 was the configure option
      `--with-openssl_dir` specified? (Linux Specific)
   7. If building from OpenSSL prebuilt RPM Package, has the OpenSSL developement
      packages (openssl-devel for Redhat* based distribution and libssl-devel
      for Debian* based distibution) been installed ?
   8. Incase of qat_sw acceleration, has the dependant libraries are installed in
      the default path or provide the path via `--with-qat_sw_crypto_mb_install_dir`
      (for crypto_mb) and `--with-qat_sw_ipsec_mb_install_dir` (for ipsec_mb) if
      installed in the path other than default.

If running on a Debian\* based OS (Ubuntu\* for example) it is possible that the
Intel&reg; QAT Driver userspace shared library needed by the Intel&reg; QAT
OpenSSL\* Engine may not be located even though it has been installed. To
resolve this it is recommended to add the /lib64 folder to the LD_LIBRARY_PATH
environment variable as follows:

    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/lib64

If building against OpenSSL\* 1.1.1 or master branch , it is possible that the
OpenSSL\* Engine will fail to build with an error message `configdata.pm not
present in the @INC path`. To resolve this, it is recommended to add the
OpenSSL source path to the PERL5LIB environment variable as follows:

    export PERL5LIB=$PERL5LIB:/path/to/openssl

If seeing failures with USDM memory allocation, either with non-root or root user
check memlock limit with `ulimit -l` and increase the memlock limit to
desired value if it is low.
