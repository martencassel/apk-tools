# Alpine Package Keeper

Alpine Package Keeper (apk) is a package manager developed for Alpine Linux.

Online documentation is available in the [doc/](doc/) directory in the form of man pages.

# Debugging

In the screenshot below we can see the buffer that will be sha1sum:ed using EVP_DigestUpdate.
When studying this buffer we see that its the APK file, with the GZIP header bytes "1F 8B 08 00" and there are 3 of them.

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

apk_extract_v2

```
sctx:
    r
    action
    is_gunzip_mpart:
      ptr: 0x00
      end: 0x00
      buf: <ptr>
      buf_size: 131072
      err: 0
      flags: 0
      ops (gunzip_istream_ops: get_meta, read, close)
    id_cache:
      root_fd: 0, uid_cache, gid_cache
    ectx:
      ac:
      ops <extract_pkgmeta_ops> v2index, v2meta
      identity:
        data:
        type:
      desc
      generate_identity: 1
    is:
      ptr, end, buf, buf_size; err, ops: (get_meta, read, close)

```

apk_tar_parse:

```
        Locals:
        entry:
          name: ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
          link_target: 0x0
          uname: ""
          gname: ""
          size: 512
          uid: 0
          gid: 0
          mode: 33188
          mtime: 1630625674
          device: 0
          xattr_digest
          xattrs: <dummy_array>
        segment:
        buf: 0
        end: 0

		if (entry.mode & S_IFMT) {
			apk_istream_segment(&segment, is, entry.size, entry.mtime);
			r = parser(ctx, &entry, &segment.is);
			if (r != 0) goto err;
			apk_istream_close(&segment.is);

			entry.name = buf.name;
			toskip -= entry.size;
			paxlen = 0;
		}
```
