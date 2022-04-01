# Alpine Package Keeper

Alpine Package Keeper (apk) is a package manager developed for Alpine Linux.

Online documentation is available in the [doc/](doc/) directory in the form of man pages.

# Debugging
If we assume that the Q:1xxx value is a SHA1, we then find the line that computes a SHA1 sum. In APK it's EVP_DigestUpdate.
When studying the buffer argument to this function  we see that it points to second .tar.gz file in the APK file,
with the GZIP header bytes "1F 8B 08 00" and there are 3 of them.

![alt text](EVP_Digest_Final_1.png)


# SHA1 example

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

 
