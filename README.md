libssh2-hs README
=================

[![Build Status](https://travis-ci.org/portnov/libssh2-hs.svg?branch=master)](https://travis-ci.org/portnov/libssh2-hs)

This repository contains two closely related packages.

libssh2
-------

This package provides FFI bindings for SSH2 client library named libssh2.

As of version 0.2 all blocking is handled in Haskell code rather than in C
code. This means that all calls are now interruptable using Haskell
asynchronous exceptions; for instance, it is now possible to use System.Timeout
in combination with "libssh2".

Note on usage on Windows: On Windows you MUST compile your executable with
-threaded or libssh2 will NOT work. We have tested libssh2 on Windows using
http://mingw.org/, with http://www.openssl.org/ and http://libssh2.org/
compiled from source (be sure to pass the shared option to the configure script
for openssl to enable the shared libraries).

libssh2-conduit
---------------

This package provides Conduit interface (see conduit package) for libssh2 FFI
bindings (see libssh2 package). This allows one to receive data from SSH
channels lazily, without need to read all channel output to the memory.

