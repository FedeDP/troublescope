/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

// This consts file is shared between the plugin and tests

/////////////////////////
// Async capability
/////////////////////////
#define ASYNC_EVENT_ROOT_NAME "diagnostic_dir"
#define ASYNC_EVENT_PID_NAME "diagnostic_pid"
#define ASYNC_EVENT_ENTRY_NAME "diagnostic_entry"
#define ASYNC_EVENT_NAME "diagnostic"
#define ASYNC_EVENT_NAMES \
	{ASYNC_EVENT_NAME, ASYNC_EVENT_ROOT_NAME, ASYNC_EVENT_PID_NAME, ASYNC_EVENT_ENTRY_NAME}
#define ASYNC_EVENT_SOURCES {"syscall"}

/////////////////////////
// Extract capability
/////////////////////////
#define EXTRACT_EVENT_NAMES {""}

#define EXTRACT_EVENT_SOURCES {"syscall"}

/////////////////////////
// Parse capability
/////////////////////////
#define PARSE_EVENT_CODES {PPME_ASYNCEVENT_E}

#define PARSE_EVENT_SOURCES {"syscall"}

/////////////////////////
// Table fields
/////////////////////////
#define THREAD_TABLE_NAME "threads"
#define TID_FIELD_NAME "tid"
#define COMM_FIELD_NAME "comm"
#define EXE_FIELD_NAME "exe"
#define CWD_FIELD_NAME "cwd"

/////////////////////////
// Metrics
/////////////////////////
#define METRIC_N_PROCS "n_procs"
#define METRIC_N_MISSING "n_missing_procs"

/////////////////////////
// Generic plugin consts
/////////////////////////
#define PLUGIN_NAME "troublescope"
#define PLUGIN_VERSION "0.1.0"
#define PLUGIN_DESCRIPTION "Falco proc tree diagnostic plugin"
#define PLUGIN_CONTACT "github.com/falcosecurity/plugins"
#define PLUGIN_REQUIRED_API_VERSION "3.10.0"
