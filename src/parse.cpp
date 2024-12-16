#include <sstream>
#include <unordered_map>
#include "falcosecurity/async_event_handler.h"
#include "falcosecurity/table.h"
#include "plugin.h"

//////////////////////////
// Parse capability
//////////////////////////

// We need to parse only the async events produced by this plugin. The async
// events produced by this plugin are injected in the syscall event source,
// so here we need to parse events coming from the "syscall" source.
// We will select specific events to parse through the
// `get_parse_event_types` API.
std::vector<std::string> my_plugin::get_parse_event_sources() {
	return PARSE_EVENT_SOURCES;
}

std::vector<falcosecurity::event_type> my_plugin::get_parse_event_types() {
	return PARSE_EVENT_CODES;
}

void my_plugin::parse_root_async_event(const falcosecurity::parse_event_input &in) {
	auto &tr = in.get_table_reader();
	m_threads_table.iterate_entries(tr, [this, tr](const falcosecurity::table_entry &e) {
		int64_t tid;
		m_threads_field_tid.read_value(tr, e, tid);
		m_context.filler(m_context.buf,
		                 std::to_string(tid).c_str(),
		                 NULL,
		                 0,
		                 static_cast<enum fuse_fill_dir_flags>(0));
		return true;
	});
}

void my_plugin::parse_pid_async_event(const falcosecurity::parse_event_input &in) {
	m_context.filler(m_context.buf,
	                 COMM_FIELD_NAME,
	                 NULL,
	                 0,
	                 static_cast<enum fuse_fill_dir_flags>(0));
	m_context.filler(m_context.buf,
	                 EXE_PATH_FILENAME,
	                 NULL,
	                 0,
	                 static_cast<enum fuse_fill_dir_flags>(0));
	m_context.filler(m_context.buf,
	                 CWD_FIELD_NAME,
	                 NULL,
	                 0,
	                 static_cast<enum fuse_fill_dir_flags>(0));
	m_context.filler(m_context.buf, "fdinfo", NULL, 0, static_cast<enum fuse_fill_dir_flags>(0));
	m_context.filler(m_context.buf,
	                 CGROUP_FIELD_NAME,
	                 NULL,
	                 0,
	                 static_cast<enum fuse_fill_dir_flags>(0));
	m_context.filler(m_context.buf,
	                 CMDLINE_FILENAME,
	                 NULL,
	                 0,
	                 static_cast<enum fuse_fill_dir_flags>(0));
}

void my_plugin::parse_fd_root_async_event(const falcosecurity::parse_event_input &in) {
	m_context.filler(m_context.buf, "name", NULL, 0, static_cast<enum fuse_fill_dir_flags>(0));
}

void my_plugin::parse_entry_async_event(const falcosecurity::parse_event_input &in) {
	using st = falcosecurity::state_value_type;

	auto &evt = in.get_event_reader();
	falcosecurity::events::asyncevent_e_decoder dec(evt);
	auto &tr = in.get_table_reader();

	uint32_t len = 0;
	const char *field = (char *)dec.get_data(len);
	const auto tid = evt.get_tid();
	try {
		const auto tinfo = m_threads_table.get_entry(tr, static_cast<int64_t>(tid));
		if(!strcmp(field, COMM_FIELD_NAME)) {
			std::string comm;
			m_threads_field_comm.read_value(tr, tinfo, comm);
			comm += '\n';
			memcpy(m_context.buf, comm.c_str(), comm.length() + 1);
		}
		if(!strcmp(field, EXE_PATH_FILENAME)) {
			std::string exe_path;
			m_threads_field_exe_path.read_value(tr, tinfo, exe_path);
			memcpy(m_context.buf, exe_path.c_str(), exe_path.length() + 1);
		}
		if(!strcmp(field, CWD_FIELD_NAME)) {
			std::string cwd;
			m_threads_field_cwd.read_value(tr, tinfo, cwd);
			if(cwd.empty()) {
				// If the cwd is empty, we set it to the root directory
				cwd = "/";
			}
			memcpy(m_context.buf, cwd.c_str(), cwd.length() + 1);
		}
		if(!strcmp(field, "fdinfo")) {
			auto fd_table = m_threads_table.get_subtable(tr,
			                                             m_threads_field_file_descriptors,
			                                             tinfo,
			                                             st::SS_PLUGIN_ST_INT64);
			fd_table.iterate_entries(tr, [this, tr](const falcosecurity::table_entry &e) {
				int64_t fd;
				m_fd_field_fd.read_value(tr, e, fd);
				m_context.filler(m_context.buf,
				                 std::to_string(fd).c_str(),
				                 NULL,
				                 0,
				                 static_cast<enum fuse_fill_dir_flags>(0));
				return true;
			});
		}
		if(!strcmp(field, CGROUP_FIELD_NAME) && m_has_cgroups) {
			// Support only cgroup v2 layout.
			std::string cgroup_pathname;
			auto cgroups_table = m_threads_table.get_subtable(
			        tr,
			        m_threads_field_cgroups,
			        tinfo,
			        falcosecurity::state_value_type::SS_PLUGIN_ST_UINT64);
			cgroups_table.iterate_entries(tr, [&](const falcosecurity::table_entry &e) {
				std::string pathname;
				m_cgroups_field_second.read_value(tr, e, pathname);
				// Avoid collecting all nested pathnames; instead collect only the longest one
				// (which is the most nested one).
				if(pathname.length() > cgroup_pathname.length()) {
					cgroup_pathname = pathname;
				}
				return true;
			});

			cgroup_pathname = "0::" + cgroup_pathname + '\n';
			memcpy(m_context.buf, cgroup_pathname.c_str(), cgroup_pathname.length() + 1);
		}
		if(!strcmp(field, CMDLINE_FILENAME)) {
			std::ostringstream oss;

			// Output argv[0]
			std::string exe;
			m_threads_field_exe.read_value(tr, tinfo, exe);
			oss << exe;

			// Output argv[1:]
			auto args_table = m_threads_table.get_subtable(
			        tr,
			        m_threads_field_args,
			        tinfo,
			        falcosecurity::state_value_type::SS_PLUGIN_ST_UINT64);
			args_table.iterate_entries(tr, [&](const falcosecurity::table_entry &e) {
				std::string arg;
				m_args_field_value.read_value(tr, e, arg);
				oss << ' ' << arg;
				return true;
			});
			oss << '\n';
			auto cmdline = oss.str();
			memcpy(m_context.buf, cmdline.c_str(), cmdline.length() + 1);
		}

	} catch(std::exception &e) {
		SPDLOG_ERROR("entry parse error for tid {} and field {}: {}", tid, field, e.what());
	}
}

void my_plugin::parse_diff_async_event(const falcosecurity::parse_event_input &in) {
	auto &tr = in.get_table_reader();
	m_threads_table.iterate_entries(tr, [&](const falcosecurity::table_entry &e) {
		int64_t tid;
		m_threads_field_tid.read_value(tr, e, tid);
		proc_entry sinsp_comm(proc_entry::from_thread_table(m_threads_field_comm,
		                                                    tr,
		                                                    e,
		                                                    tid,
		                                                    proc_entry::proc_file::comm));
		m_context.sinsp_entries.insert({sinsp_comm.path, sinsp_comm});
		proc_entry proc_comm(proc_entry::from_proc_fs(sinsp_comm.path));
		if(!proc_comm.path.empty()) {
			m_context.proc_entries.insert({proc_comm.path, proc_comm});
		}
		return true;
	});
}

bool my_plugin::parse_async_event(const falcosecurity::parse_event_input &in) {
	falcosecurity::events::asyncevent_e_decoder ad(in.get_event_reader());

	bool is_root = std::strcmp(ad.get_name(), ASYNC_EVENT_ROOT_NAME) == 0;
	bool is_pid = std::strcmp(ad.get_name(), ASYNC_EVENT_PID_NAME) == 0;
	bool is_entry = std::strcmp(ad.get_name(), ASYNC_EVENT_ENTRY_NAME) == 0;
	bool is_diff = std::strcmp(ad.get_name(), ASYNC_EVENT_DIFF_NAME) == 0;
	bool is_fd_root = std::strcmp(ad.get_name(), ASYNC_EVENT_FD_ROOT_NAME) == 0;
	if(!is_root && !is_pid && !is_entry && !is_fd_root && !is_diff) {
		// We are not interested in parsing async events that are not
		// generated by our plugin.
		// This is not an error, it could happen when we have more than one
		// async plugin loaded.
		return true;
	}

	if(is_root) {
		parse_root_async_event(in);
	}
	if(is_pid) {
		parse_pid_async_event(in);
	}
	if(is_entry) {
		parse_entry_async_event(in);
	}
	if(is_diff) {
		parse_diff_async_event(in);
	}
	if(is_fd_root) {
		parse_fd_root_async_event(in);
	}

	std::unique_lock l(m_context.m_mu);
	m_context.done = true;
	m_context.m_cv.notify_all();
	return true;
}

bool my_plugin::parse_event(const falcosecurity::parse_event_input &in) {
	// NOTE: today in the libs framework, parsing errors are not logged
	auto &evt = in.get_event_reader();

	switch(evt.get_type()) {
	case PPME_ASYNCEVENT_E:
		return parse_async_event(in);
	default:
		SPDLOG_ERROR("received an unknown event type {}", int32_t(evt.get_type()));
		return false;
	}
}

FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
