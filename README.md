# Alpine Package Keeper

## Motiviations for this fork

This fork was setup to answer the following questions:

* How are apk package checksums calculated in the APK INDEX ? 

https://stackoverflow.com/questions/38837679/alpine-apk-package-repositories-how-are-the-checksums-calculated

* How is the APKINDEX format ? 

* How is the .PKGINFO format ? 

* How do you implement the apk index command in another implementation ? 

## Devcontainer
This repo contains a devcontainer with
  - Debugging apk index command
  - Dev dependencies from apk

See https://github.com/martencassel/apk-tools/tree/master/.devcontainer
See https://github.com/martencassel/apk-tools/blob/master/Dockerfile

## Conclusions:

With the help of debugging i got the above answered:


```
APKINDEX

C:Q1eiZkJd97/XzppCxxoBXqKuVxWDg=                Pull checksum   - sha1sum of second .tar.gz of APK file ( = concatenation of 3 .targz files)
P:strace                                        Package Name                     .PKGINFO.pkgname
V:5.14-r0                                       Package version                  .PKGINFO.pkgver
A:x86_64                                        Architecture                     .PKGINFO.arch
S:488249                                        Package Size                     ls -lt strace-5.14-r0.apk
I:1601536                                       Package Installed Size           .PKGINFO.size
T:Diagnostic, debugging and instructional userspace tracer   Package Description .PKGINFO.pkgdesc
U:https://strace.io                             Package URL             .PKGINFO.url
L:BSD-3-Clause                                  License                 .PKGINFO.license
o:strace                                        Package Origin          .PKGINFO.origin
m:Natanael Copa <ncopa@alpinelinux.org>         Maintainer              .PKGINFO.maintainer
t:1630625674                                    Build Timestamp         .PKGINFO.builddate
c:aae0222b915a0985e775ce126c01793a3a95716a      Git commit of aport     .PKGINFO.commit
D:so:libc.musl-x86_64.so.1 so:libdw.so.1        Pull dependencies       .PKGINFO.depend[]
p:cmd:strace-log-merge=5.14-r0 cmd:strace=5.14-r0  Package Provides     .PKGINFO.provides[]

.PKGINFO

# Generated by abuild 3.9.0_rc2-r1
# using fakeroot version 1.25.3
# Thu Sep  2 23:34:34 UTC 2021
pkgname = strace
pkgver = 5.14-r0
pkgdesc = Diagnostic, debugging and instructional userspace tracer
url = https://strace.io
builddate = 1630625674
packager = Buildozer <alpine-devel@lists.alpinelinux.org>
size = 1601536
arch = x86_64
origin = strace
commit = aae0222b915a0985e775ce126c01793a3a95716a
maintainer = Natanael Copa <ncopa@alpinelinux.org>
license = BSD-3-Clause
# automatically detected:
provides = cmd:strace-log-merge=5.14-r0
provides = cmd:strace=5.14-r0
depend = so:libc.musl-x86_64.so.1
depend = so:libdw.so.1
datahash = c85ee742cf10a552bcbfafc731b9f2efeed02bc3f3317567b287ba8cf2c1d7fd             # sha256sum file_3.tar.gz

```

Reference: https://wiki.alpinelinux.org/wiki/Apk_spec

# The approach 

How to find the identity checksum of specific packages in the APKINDEX records ? 
(It's not available in .PKGINFO), but in one of the .gz files that the apk consists of.

One conclusion is that GZIP files consists of a set of GZIP files, that is concatenated.
APK uses this scheme, so one APK is a concatenation of 3 gzip files.

# Debugging reasoning to find SHA1 in the apk index code path:

We backtrack from the code that performs the SHA1 operation, and track working variables.

If we assume that the Q:1xxx value is a SHA1, we then find the line that computes a SHA1 sum. 
Because they use C, we learn how its implemented using the openssl library.

In APK it's EVP_DigestUpdate, we then set a breakpoint on this function.

When studying the buffer argument to this function  we see that it points to second .tar.gz file in the APK file,
with the GZIP header bytes "1F 8B 08 00" and there are 3 of them.

![alt text](EVP_Digest_Final_1.png)
 
 
# SHA1 example in C for openssl

```C
#include <openssl/evp.h>
#include <openssl/rand.h>

void
sha1(char *buf, int len) {
    EVP_MD_CTX md_ctx;
    unsigned int md_len;
    unsigned char md_value[EVP_MAX_MD_SIZE];

    EVP_MD_CTX_init(&md_ctx);
    EVP_DigestInit_ex(&md_ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(&md_ctx, buf, len);
    EVP_DigestFinal_ex(&md_ctx, md_value, &md_len);
    EVP_MD_CTX_cleanup(&md_ctx);
}
```

https://gist.github.com/ytakano/964119

 
