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


# Callstack of index_main

```
apk_tar_parse(struct apk_istream * is, apk_archive_entry_parser parser, void * ctx, struct apk_id_cache * idc) (/src/src/tar.c:133)
apk_extract_v2(struct apk_extract_ctx * ectx, struct apk_istream * is) (/src/src/extract_v2.c:359)
    ...
    apk_sign_ctx_init(&sctx, action, ectx->identity, trust);
    struct apk_istream* is_gunzip_mpart = apk_istream_gunzip_mpart(is, apk_sign_ctx_mpart_cb, &sctx);
  	struct apk_id_cache* id_cache       = apk_ctx_get_id_cache(ac);

	r = apk_tar_parse(is_gunzip_mpart, apk_extract_v2_entry, ectx, id_cache);
    ...
    return r
apk_pkg_read(struct apk_database * db, const char * file, struct apk_package ** pkg, int v3ok) (/src/src/package.c:722)
index_main(void * ctx, struct apk_ctx * ac, struct apk_string_array * args) (/src/src/app_index.c:188)
main(int argc, char ** argv) (/src/src/apk.c:533)
```
