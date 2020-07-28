/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/common_defines.h"
#include <netinet/ether.h>

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif


