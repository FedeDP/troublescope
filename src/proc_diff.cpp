#include "proc_diff.h"

#include <filesystem>
#include <fstream>
#include <sstream>

proc_entry proc_entry::from_proc_fs(const std::string& path) {
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
proc_entry proc_entry::from_thread_table(falcosecurity::table_field& tf,
                                         const falcosecurity::table_reader& tr,
                                         const falcosecurity::table_entry& e,
                                         const int tid,
                                         proc_file pf) {
	proc_entry entry;
	entry.tid = tid;
	tf.read_value(tr, e, entry.content);
	switch(pf) {
	case proc_file::comm:
		entry.is_symlink = false;
		entry.path = fmt::format("comm", tid);
		break;
	case proc_file::exe:
		entry.is_symlink = true;
		entry.path = fmt::format("exe", tid);
		break;
	case proc_file::cwd:
		entry.path = fmt::format("cwd", tid);
		entry.is_symlink = true;
		break;
	}
	return entry;
}
