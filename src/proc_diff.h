/*
Copyright (C) 2024 The Falco Authors.

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

#include "falcosecurity/table.h"

#include <fmt/core.h>

#include <string>

struct proc_entry {
	enum class proc_file {
		comm,
		exe,
		cwd,
	};
	std::string path = "";
	bool is_symlink = false;
	std::string content = "";
	int tid;

	std::string to_string() const {
		return fmt::format("path: '{}', is_symlink: '{}', content: '{}'",
		                   path,
		                   is_symlink,
		                   content);
	}

	// returns field name from path
	std::string proc_file_str() const { return path.substr(path.find_last_of("/") + 1); }

	bool operator==(const proc_entry& other) const {
		return path == other.path && is_symlink == other.is_symlink && content == other.content;
	}
	bool operator!=(const proc_entry& other) const { return !(*this == other); }
	static proc_entry from_proc_fs(const std::string& path);
	static proc_entry from_thread_table(falcosecurity::table_field& tf,
	                                    const falcosecurity::table_reader& tr,
	                                    const falcosecurity::table_entry& e,
	                                    const int tid,
	                                    proc_file pf);
};

using not_found_proc_entry = proc_entry;

using proc_diff = std::pair<proc_entry, proc_entry>;
