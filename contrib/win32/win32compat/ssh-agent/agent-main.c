/*
 * Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
 * ssh-agent implementation on Windows
 * NT Service routines
 *
 * Copyright (c) 2015 Microsoft Corp.
 * All rights reserved
 *
 * Microsoft openssh win32 port
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "agent.h"
#include "..\misc_internal.h"
#include "..\Debug.h"
#include <wchar.h>

/*set current working directory to module path*/
static void
fix_cwd()
{
	wchar_t path[PATH_MAX] = { 0 };
	int i, lastSlashPos = 0;
	GetModuleFileNameW(NULL, path, PATH_MAX);
	for (i = 0; path[i]; i++) {
		if (path[i] == L'/' || path[i] == L'\\')
			lastSlashPos = i;
	}

	path[lastSlashPos] = 0;
	_wchdir(path);
}

/* TODO - get rid of this dependency */
void log_init(char*, int, int, int);

int 
wmain(int argc, wchar_t **argv) 
{
	_set_invalid_parameter_handler(invalid_parameter_handler);
	w32posix_initialize();
	fix_cwd();
	start_managed_worker();
	agent_start(TRUE);
	return 0;
}

#pragma warning(pop)
