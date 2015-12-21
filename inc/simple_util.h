
#pragma once

#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <tzplatform_config.h>

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#ifdef AMD_LOG
#undef LOG_TAG
#define LOG_TAG "AUL_AMD"
#endif

#define MAX_LOCAL_BUFSZ 128
#define MAX_PID_STR_BUFSZ 20
#define MAX_UID_STR_BUFSZ 20
#define AUL_UTIL_PID -2

#define MAX_PACKAGE_STR_SIZE 512
#define MAX_PACKAGE_APP_PATH_SIZE 512
#define MAX_RUNNING_APP_INFO 512

#define GSLIST_FOREACH_SAFE(list, l, l_next)   \
	for (l = list,                            \
			l_next = g_slist_next(l);       \
			l;                              \
			l = l_next,                     \
			l_next = g_slist_next(l))

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

int __proc_iter_appid(int (*iterfunc)
			 (const char *dname, const char *appid, void *priv, uid_t uid),
			void *priv);
int __proc_iter_pgid(int pgid, int (*iterfunc) (int pid, void *priv, uid_t uid),
		     void *priv);
char *__proc_get_appid_bypid(int pid);
char *__proc_get_cmdline_bypid(int pid);
char *__proc_get_exe_bypid(int pid);
uid_t __proc_get_usr_bypid(int pid);

static inline const char *FILENAME(const char *filename)
{
	const char *p;
	const char *r;

	if (!filename)
		return NULL;

	r = p = filename;
	while (*p) {
		if (*p == '/')
			r = p + 1;
		p++;
	}

	return r;
}

