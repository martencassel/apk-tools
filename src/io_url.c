/* io_url.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <fetch.h>

#include "apk_io.h"

const char *apk_url_local_file(const char *url)
{
	if (strncmp(url, "file:", 5) == 0)
		return &url[5];

	if (strncmp(url, "http:", 5) != 0 &&
	    strncmp(url, "https:", 6) != 0 &&
	    strncmp(url, "ftp:", 4) != 0)
		return url;

	return NULL;
}

struct apk_fetch_istream {
	struct apk_istream is;
	fetchIO *fetchIO;
	struct url_stat urlstat;
};

static int fetch_maperror(int ec)
{
	static const signed short map[] = {
		[FETCH_ABORT] = -ECONNABORTED,
		[FETCH_AUTH] = -EACCES,
		[FETCH_DOWN] = -ECONNREFUSED,
		[FETCH_EXISTS] = -EEXIST,
		[FETCH_FULL] = -ENOSPC,
		/* [FETCH_INFO] = , */
		[FETCH_MEMORY] = -ENOMEM,
		[FETCH_MOVED] = -ENOENT,
		[FETCH_NETWORK] = -ENETUNREACH,
		/* [FETCH_OK] = , */
		[FETCH_PROTO] = -EPROTO,
		[FETCH_RESOLV] = -APKE_DNS,
		[FETCH_SERVER] = -APKE_REMOTE_IO,
		[FETCH_TEMP] = -EAGAIN,
		[FETCH_TIMEOUT] = -ETIMEDOUT,
		[FETCH_UNAVAIL] = -ENOENT,
		[FETCH_UNKNOWN] = -EIO,
		[FETCH_URL] = -APKE_URL_FORMAT,
		[FETCH_UNCHANGED] = -EALREADY,
	};

	if (ec < 0 || ec >= ARRAY_SIZE(map) || !map[ec]) return -EIO;
	return map[ec];
}

static void fetch_get_meta(struct apk_istream *is, struct apk_file_meta *meta)
{
	struct apk_fetch_istream *fis = container_of(is, struct apk_fetch_istream, is);

	*meta = (struct apk_file_meta) {
		.atime = fis->urlstat.atime,
		.mtime = fis->urlstat.mtime,
	};
}

static ssize_t fetch_read(struct apk_istream *is, void *ptr, size_t size)
{
	struct apk_fetch_istream *fis = container_of(is, struct apk_fetch_istream, is);
	ssize_t r;

	r = fetchIO_read(fis->fetchIO, ptr, size);
	if (r < 0) return -EIO;
	return r;
}

static int fetch_close(struct apk_istream *is)
{
	int r = is->err;
	struct apk_fetch_istream *fis = container_of(is, struct apk_fetch_istream, is);

	fetchIO_close(fis->fetchIO);
	free(fis);
	return r < 0 ? r : 0;
}

static const struct apk_istream_ops fetch_istream_ops = {
	.get_meta = fetch_get_meta,
	.read = fetch_read,
	.close = fetch_close,
};

static struct apk_istream *apk_istream_fetch(const char *url, time_t since)
{
	struct apk_fetch_istream *fis = NULL;
	struct url *u;
	char *flags = "Ci";
	fetchIO *io = NULL;
	int rc = -EIO;

	u = fetchParseURL(url);
	if (!u) {
		rc = -APKE_URL_FORMAT;
		goto err;
	}
	fis = malloc(sizeof *fis + apk_io_bufsize);
	if (!fis) {
		rc = -ENOMEM;
		goto err;
	}

	if (since != APK_ISTREAM_FORCE_REFRESH) {
		u->last_modified = since;
		flags = "i";
	}

	io = fetchXGet(u, &fis->urlstat, flags);
	if (!io) {
		rc = fetch_maperror(fetchLastErrCode);
		goto err;
	}

	*fis = (struct apk_fetch_istream) {
		.is.ops = &fetch_istream_ops,
		.is.buf = (uint8_t*)(fis+1),
		.is.buf_size = apk_io_bufsize,
		.fetchIO = io,
		.urlstat = fis->urlstat,
	};
	fetchFreeURL(u);

	return &fis->is;
err:
	if (u) fetchFreeURL(u);
	if (io) fetchIO_close(io);
	if (fis) free(fis);
	return ERR_PTR(rc);
}

struct apk_istream *apk_istream_from_fd_url_if_modified(int atfd, const char *url, time_t since)
{
	if (apk_url_local_file(url) != NULL)
		return apk_istream_from_file(atfd, apk_url_local_file(url));
	return apk_istream_fetch(url, since);
}
