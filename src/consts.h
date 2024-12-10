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

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE

#include <falcosecurity/sdk.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

// Sinsp events used in the plugin
using _et = falcosecurity::event_type;
constexpr auto PPME_ASYNCEVENT_E = (_et)402;
