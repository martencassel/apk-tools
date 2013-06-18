/* fix.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"
#include "apk_solver.h"

struct fix_ctx {
	unsigned short solver_flags;
	int fix_depends : 1;
	int fix_directory_permissions : 1;
};

static int fix_parse(void *pctx, struct apk_db_options *dbopts,
		     int optch, int optindex, const char *optarg)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;
	switch (optch) {
	case 'd':
		ctx->fix_depends = 1;
		break;
	case 'u':
		ctx->solver_flags |= APK_SOLVERF_UPGRADE;
		break;
	case 'r':
		ctx->solver_flags |= APK_SOLVERF_REINSTALL;
		break;
	case 0x10000:
		ctx->fix_directory_permissions = 1;
		break;
	default:
		return -1;
	}
	return 0;
}

static int mark_recalculate(apk_hash_item item, void *ctx)
{
	struct apk_db_dir *dir = (struct apk_db_dir *) item;
	dir->recalc_mode = 1;
	return 0;
}

static void set_solver_flags(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;

	apk_solver_set_name_flags(name, ctx->solver_flags, ctx->fix_depends ? ctx->solver_flags : 0);
}

static int fix_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;

	if (!ctx->solver_flags)
		ctx->solver_flags = APK_SOLVERF_REINSTALL;

	if (ctx->fix_directory_permissions)
		apk_hash_foreach(&db->installed.dirs, mark_recalculate, db);

	apk_name_foreach_matching(db, args, apk_foreach_genid(), set_solver_flags, ctx);

	return apk_solver_commit(db, 0, db->world);
}

static struct apk_option fix_options[] = {
	{ 'd',		"depends",	"Fix all dependencies too" },
	{ 'u',		"upgrade",	"Upgrade package if possible" },
	{ 'r',		"reinstall",	"Reinstall the package" },
	{ 0x10000,	"directory-permissions", "Reset all directory permissions" },
};

static struct apk_applet apk_fix = {
	.name = "fix",
	.help = "Repair package or upgrade it without modifying main "
		"dependencies.",
	.arguments = "PACKAGE...",
	.open_flags = APK_OPENF_WRITE,
	.context_size = sizeof(struct fix_ctx),
	.num_options = ARRAY_SIZE(fix_options),
	.options = fix_options,
	.parse = fix_parse,
	.main = fix_main,
};

APK_DEFINE_APPLET(apk_fix);

