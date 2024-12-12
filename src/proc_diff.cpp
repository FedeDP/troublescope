#include "proc_diff.h"

#include <filesystem>
#include <fstream>
#include <sstream>

proc_entry proc_entry::from_proc_fs(const proc_entry& entry, std::string_view prefix) {
	namespace fs = std::filesystem;
	proc_entry out_entry;
	std::string path = entry.proc_file_str(prefix);
	// Read the file from the proc filesystem
	if(!fs::exists(entry.proc_file_str(prefix))) {
		return entry;
	}
	out_entry.path = entry.path;
	out_entry.tid = entry.tid;
	if(std::filesystem::is_symlink(path)) {
		out_entry.is_symlink = true;
		out_entry.content = fs::read_symlink(path).string();
	} else if(std::filesystem::is_regular_file(path)) {
		out_entry.is_symlink = false;
		std::ifstream file(path);
		std::stringstream buffer;
		buffer << file.rdbuf();
		out_entry.content = buffer.str();
		// Remove the trailing newline
		if(!out_entry.content.empty() && entry.content.back() == '\n') {
			out_entry.content.pop_back();
		}
	}
	return out_entry;
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
		entry.path = "comm";
		break;
	case proc_file::exe:
		entry.is_symlink = true;
		entry.path = "exe";
		break;
	case proc_file::cwd:
		entry.path = "cwd";
		entry.is_symlink = true;
		break;
	}
	return entry;
}
