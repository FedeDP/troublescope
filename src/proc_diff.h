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

#include <filesystem>
#include <fstream>
#include <string>
#include <sstream>

struct proc_entry {
	enum class proc_file {
		comm,
		exe,
		cwd,
	};
	std::string path = "";
	bool is_symlink = false;
	std::string content = "";

	std::string to_string() const {
		std::stringstream ss;
		ss << "path: " << path << ", is_symlink: " << is_symlink << ", content: " << content;
		return ss.str();
	}
	bool operator==(const proc_entry& other) const {
		return path == other.path && is_symlink == other.is_symlink && content == other.content;
	}
	bool operator!=(const proc_entry& other) const { return !(*this == other); }
	static proc_entry from_proc_fs(const std::string& path) {
		namespace fs = std::filesystem;
		proc_entry entry;
		// Read the file from the proc filesystem
		if(!fs::exists(path)) {
			return entry;
		}
		entry.path = path;
		if(std::filesystem::is_symlink(path)) {
			entry.is_symlink = true;
			entry.content = fs::read_symlink(path).string();
		} else if(std::filesystem::is_regular_file(path)) {
			entry.is_symlink = false;
			std::ifstream file(path);
			std::stringstream buffer;
			buffer << file.rdbuf();
			entry.content = buffer.str();
			// Remove the trailing newline
			if(!entry.content.empty() && entry.content.back() == '\n') {
				entry.content.pop_back();
			}
		}
		return entry;
	}
	static proc_entry from_thread_table(falcosecurity::table_field& tf,
	                                    const falcosecurity::table_reader& tr,
	                                    const falcosecurity::table_entry& e,
	                                    const int tid,
	                                    proc_file pf) {
		proc_entry entry;
		tf.read_value(tr, e, entry.content);
		switch(pf) {
		case proc_file::comm:
			entry.is_symlink = false;
			entry.path = fmt::format("/proc/{}/comm", tid);
			break;
		case proc_file::exe:
			entry.is_symlink = true;
			entry.path = fmt::format("/proc/{}/exe", tid);
			break;
		case proc_file::cwd:
			entry.path = fmt::format("/proc/{}/exe", tid);
			entry.is_symlink = true;
			break;
		}
		return entry;
	}
};

using not_found_proc_entry = proc_entry;

using proc_diff = std::pair<proc_entry, proc_entry>;
