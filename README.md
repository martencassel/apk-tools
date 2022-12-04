```bash
- APK v2 package/index terminology

record                      A 512 byte sequence of bytes, a block
h                           Header record
d                           Data record
e1, e2                      Eof markers (two blocks 1024 bytes)
tar archive                 A tar archive file, consiting of a set of files, a sequence of blocks ending with the eof marker blocks.
tar segment                 A set of tar records, a sequence of tar records withouth a ending eof marker.
gzip stream                 A stream is a sequence gzip compressed data, starting with a magic number, headers, body and an ending 8-byte trailer.
[ ... ]                     A gzip stream containing blocks
concatenate                 To link togther things in a series or chain. ie. concatenate.
                            Concatenate 3 gzip streams sequentially in a file.
package signature           A single file that is a binary signature over the concatenated (control + data) gzip streams
package signature file      DigestRSA-PKCS1v15(SHA1( apk-gzip-stream-2 ++ apk-gzip-stream-3), DER)
index signature file        DigestRSA-PKCS1v15(SHA1( index-gzip-stream-2), DER)
h                           A tar header record block
h1                          Signature file header, permission 0644, uid 0 and gid 0.
C: checksum                 The SHA1 hash of the "Control data" gzip stream (gzip stream 2)
```

```bash
- APK v2 package layout

Gzip                  apk-gzip-stream1       apk-gzip-stream2            apk-gzip-stream-3

Tar                   Tar segment 1          Tar segment 2               Tarball

Blocks                [h1, d]                [ h, d, h d ]               [ h, d, h, d, ..., e1, e2 ]

Files                 Package signature      Control data                Package data

- Index v2 format

Gzip                  index-gzip-stream1                index-gzip-stream2

Tar                   Tar segment 1                     Tarball

Blocks                [h1, d, ...]                      [h, d, ..., d1, d2]

Files                 .SIGN.RSA.<key_name>.rsa.pub      A DESCRIPTION file and an APKINDEX file

-----------------------------------------------------------------------------------------------------------------
```

```bash
Examples

- Create a unsigned APKINDEX file 
> apk index *.apk -o APKINDEX.unsigned.tar.gz && \

- Create a index signature file (.SIGN.RSA.marten.rsa.pub)
> openssl dgst -sha1 -sign marten.rsa.priv -out .SIGN.RSA.marten.rsa.pub APKINDEX.unsigned.tar.gz

- Create a signed APKINDEX file (1)
> tar -c .SIGN.RSA.marten.rsa.pub | abuild-tar --cut | gzip -9 > signature.tar.gz && \
> cat signature.tar.gz APKINDEX.unsigned.tar.gz > APKINDEX.tar.gz
```

- What is a tar file ? 
An archive created by tar, utility. 
It contains multiple files (aka. tarball) stored in an uncompressed format along with metadata about the archive.
An archive may contain many files, the archive itself is a single file.

- What format has a tar file ? 
A series of file entries terminated by an end-of-archive entry.
The end-of-archive entry consists of two 512 blocks of zero bytes.
A file entry describes one of the files in the archive. The file entry consists 
of a file header and the contents of the file. File headers contain file names etc.

- What is the file layout of tar file ? 
A archive file contains a series of blocks. Each block contains BLOCKSIZE bytes.
Usually the BLOCKSIZE is 512 bytes.

- What is the layout of a file in a tar archive ? 
Each file is represented by a header block, with metadata about the file.
Followed by zero or more blocks which give the contents of the file.
At the end of the archive file there are two 512 byte blocks 
filled with zeroes as an end-of-file marker.

- What is the physical definition of a tar file ? 
A linear sequence of blocks. The file is terminated by two blocks of zero bytes. 
Every block has the size 512 bytes.
A tar file consists of file entries, and each file entry is represented by two or more blocks.
First block is always the entry header, rest is content of the file.

- What is a segment ? 
A portion of a file. Portions of a tar file (segments).

- What is a record ? 
The end of a normal tar file contains two null records (blocks) at the end.

- What is a sequence ? 
An enumerated collection of objects in which repetition are allowed and order matters.

- What is a stream ? 
A sequence of data elements made available over time. They are processed one at a time, rather in large batches.

* Archive consists of a series of file entries terminated by an end-of-archive entry

* A tar archive file contains a series of block each 512 bytes length

* File entries
   - A file header block
   - Data blocks

* A file usually ends with a end-of-file marker (two zero blocks)



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

https://wiki.alpinelinux.org/wiki/Apk_spec
 
