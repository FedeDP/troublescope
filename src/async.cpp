#include "plugin.h"
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/poll.h>
#include <filesystem>

enum poll_fds { POLL_FD_FUSE = 0, POLL_FD_EVENTFD = 1, POLL_FD_TIMERFD = 2, POLL_FD_SIZE = 3 };

//////////////////////////
// Async capability
//////////////////////////

std::vector<std::string> my_plugin::get_async_events() {
	return ASYNC_EVENT_NAMES;
}

std::vector<std::string> my_plugin::get_async_event_sources() {
	return ASYNC_EVENT_SOURCES;
}

static void generate_async_event(const std::unique_ptr<falcosecurity::async_event_handler> &h,
                                 const std::string &event_name,
                                 int64_t tid,
                                 const std::string &msg) {
	falcosecurity::events::asyncevent_e_encoder enc;
	enc.set_tid(tid);
	enc.set_name(event_name);
	enc.set_data((char *)msg.c_str(), msg.length() + 1);

	enc.encode(h->writer());
	h->push();
}

static int fuse_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	(void)fi;

	memset(stbuf, 0, sizeof(struct stat));
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_atime = time(NULL);
	stbuf->st_mtime = time(NULL);
	if(strcmp(path, "/") == 0) {  // root dir of fuse fs
		stbuf->st_mode = S_IFDIR | 0755;
		return 0;
	}

	int pid;
	char p[32] = {};
	int ret = sscanf(path, "/%d/%31s", &pid, p);
	if(ret == 1) {
		// we only matched "/1000"
		stbuf->st_mode = S_IFDIR | 0755;
		return 0;
	}
	if(ret == 2) {
		char f[32] = {};
		int fd;
		ret = sscanf(path, "/%d/fdinfo/%d/%31s", &pid, &fd, f);
		if(ret == 2) {
			// we matched /1000/fdinfo/<fd>
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 0;  // TODO correct value
			return 0;
		}

		if(ret == 3) {
			// we matched /1000/fdinfo/<fd>/name
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_nlink = 1;
			stbuf->st_size = 1024;  // non-zero size
			return 0;
		}

		if(strcmp(p, "fdinfo") == 0) {
			// we matched /1000/fdinfo
			stbuf->st_mode = S_IFDIR | 0755;
			stbuf->st_nlink = 0;  // TODO correct value
			return 0;
		}

		// we matched /1000/foo
		if(strcmp(p, "cwd") == 0 || strcmp(p, EXE_PATH_FILENAME) == 0) {
			stbuf->st_mode = S_IFLNK | 0444;
		} else {
			stbuf->st_mode = S_IFREG | 0444;
		}
		stbuf->st_nlink = 1;
		stbuf->st_size = 1024;  // non-zero size
		return 0;
	}
	return -EINVAL;
}

static int fuse_readdir(const char *path,
                        void *buf,
                        fuse_fill_dir_t filler,
                        off_t offset,
                        struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
	{
		auto *ctx = static_cast<plugin_context *>(fuse_get_context()->private_data);
		if(ctx == NULL) {
			return -EINVAL;
		}
		if(offset != 0) {
			// Unsupported
			return -EPERM;
		}

		std::unique_lock l(ctx->m_mu);
		ctx->filler = filler;
		ctx->buf = buf;
		ctx->done = false;
		int pid = 0;
		char b[32] = {};

		if(strcmp(path, "/") == 0) {
			generate_async_event(ctx->async_event_handler, ASYNC_EVENT_ROOT_NAME, pid, "root");
		}

		int ret = sscanf(path, "/%d/%31s", &pid, b);
		if(ret == 1) {
			generate_async_event(ctx->async_event_handler, ASYNC_EVENT_PID_NAME, pid, "pid");
		}

		if(ret == 2) {
			char fd[32] = {};
			if(sscanf(path, "/%d/fdinfo/%31s", &pid, fd) == 2) {
				generate_async_event(ctx->async_event_handler, ASYNC_EVENT_FD_ROOT_NAME, pid, fd);
			} else {
				generate_async_event(ctx->async_event_handler, ASYNC_EVENT_ENTRY_NAME, pid, b);
			}
		}

		ctx->m_cv.wait(l, [ctx] { return ctx->done; });
	}
	return 0;
}

static int fuse_open(const char *path, struct fuse_file_info *fi) {
	if((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	fi->direct_io = 0;
	fi->nonseekable = 0;
	return 0;
}

// This function is used to get an entry value for a path by generating an
// ASYNC_EVENT_ENTRY_NAME event.
static int _get_entry_value(const char *path, char *buf, size_t size) {
	auto *ctx = static_cast<struct plugin_context *>(fuse_get_context()->private_data);
	if(ctx == NULL) {
		return -EINVAL;
	}

	std::unique_lock l(ctx->m_mu);
	ctx->done = false;
	memset(buf, 0, size);
	ctx->buf = buf;
	int pid = 0;
	char entry[32] = {};
	sscanf(path, "/%d/%31s", &pid, entry);
	generate_async_event(ctx->async_event_handler, ASYNC_EVENT_ENTRY_NAME, pid, entry);
	ctx->m_cv.wait(l, [ctx] { return ctx->done; });
	return strlen(buf) + 1;
}

static int fuse_read(const char *path,
                     char *buf,
                     size_t size,
                     off_t offset,
                     struct fuse_file_info *fi) {
	if(offset != 0) {
		// Unsupported
		return -EPERM;
	}
	return _get_entry_value(path, buf, size);
}

static int fuse_readlink(const char *path, char *buf, size_t size) {
	if(auto read_size = _get_entry_value(path, buf, size); read_size > 0) {
		return 0;
	}
	return -ENOENT;
};

static constexpr struct fuse_operations ops = {
        .getattr = fuse_getattr,
        .readlink = fuse_readlink,
        .open = fuse_open,
        .read = fuse_read,
        .readdir = fuse_readdir,
};

void my_plugin::async_thread_loop(std::unique_ptr<falcosecurity::async_event_handler> h) noexcept {
	struct pollfd fds[POLL_FD_SIZE];
	fds[POLL_FD_FUSE].fd = m_fuse_fd;
	fds[POLL_FD_FUSE].events = POLLIN;
	fds[POLL_FD_EVENTFD].fd = m_event_fd;
	fds[POLL_FD_EVENTFD].events = POLLIN;
	fds[POLL_FD_TIMERFD].fd = m_timer_fd;
	fds[POLL_FD_TIMERFD].events = POLLIN;

	while(true) {
		auto ret = poll(fds, std::size(fds), -1);
		switch(ret) {
		case -1:
		case 0:
			break;
		default: {
			// Process fuseFS events
			if(fds[POLL_FD_FUSE].revents & POLLIN) {
				struct fuse_session *sess = fuse_get_session(m_fuse_handler);
				ret = fuse_session_receive_buf(sess, &m_fuse_buf);
				if(ret > 0) {
					fuse_session_process_buf(sess, &m_fuse_buf);
				}
			}
			// Process eventfd exit request
			if(fds[POLL_FD_EVENTFD].revents & POLLIN) {
				// consume
				uint64_t tt;
				eventfd_read(m_event_fd, &tt);
				goto exit;
			}
			// Process timerfd events
			if(fds[POLL_FD_TIMERFD].revents & POLLIN) {
				// consume
				uint64_t tt;
				if(const auto res = read(m_timer_fd, &tt, sizeof(uint64_t)); res >= 0) {
					std::unique_lock l(m_context.m_mu);
					m_context.proc_entries.clear();
					m_context.sinsp_entries.clear();
					m_context.done = false;

					// -1 should be a valid tid for async events
					generate_async_event(h, ASYNC_EVENT_DIFF_NAME, -1, "root");
					m_context.m_cv.wait(l, [&] { return m_context.done; });

					nlohmann::json j;
					auto &j_diff = j["diff"];
					size_t diffs = 0;
					SPDLOG_DEBUG("proc_entries size: {}", m_context.proc_entries.size());
					for(const auto &e : m_context.sinsp_entries) {
						const auto sinsp_tid = e.second;
						if(m_context.proc_entries.count(e.first) > 0) {
							const auto &proc_tid = m_context.proc_entries.at(e.first);
							for(const auto &[path, sinsp_e] : sinsp_tid) {
								if(proc_tid.count(path) > 0) {
									const auto &proc_e = proc_tid.at(path);
									if(sinsp_e != proc_e) {
										diffs++;
										auto &j_entry = j_diff[std::to_string(sinsp_e.tid)];

										nlohmann::json d;
										d["field"] = sinsp_e.path;
										d["sinsp"] = sinsp_e.content;
										d["proc"] = proc_e.content;

										j_entry.push_back(d);
									}
								} else {
									// TODO: sinsp entry not found in /proc
								}
							}
						} else {
							// TODO: sinsp TID not found in /proc
						}
					}
					if(diffs > 0) {
						// real event
						generate_async_event(h, ASYNC_EVENT_NAME, -1, j.dump());
					}
				}
			}
			break;
		}
		}
	}

exit:
	SPDLOG_DEBUG("Async thread terminated");
}

// We need this API to start the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::start_async_events(std::shared_ptr<falcosecurity::async_event_handler_factory> f) {
	std::filesystem::path directory = m_cfg.fs_root;
	std::error_code ec;
	auto exists = std::filesystem::exists(directory, ec);
	if(ec.value() != 0) {
		SPDLOG_ERROR("cannot check if directory exists: {}. err: {}",
		             directory.string(),
		             ec.message());
		return false;
	}

	if(!exists) {
		if(!std::filesystem::create_directory(directory, ec)) {
			SPDLOG_ERROR("cannot create directory: {}. err: {}", directory.string(), ec.message());
			return false;
		}
	}

	SPDLOG_INFO("FUSE filesystem at {}", directory.string());
	fuse_opt_add_arg(&m_fuse_args, PLUGIN_NAME);
	m_context.async_event_handler = f->new_handler();
	m_fuse_handler = fuse_new(&m_fuse_args, &ops, sizeof(ops), &m_context);
	int ret = fuse_mount(m_fuse_handler, directory.c_str());
	if(ret != 0) {
		SPDLOG_ERROR("fuse_mount failed: {}", ret);
		return false;
	}
	m_fuse_fd = fuse_session_fd(fuse_get_session(m_fuse_handler));
	if(m_fuse_fd < 0) {
		SPDLOG_ERROR("fuse_session_fd failed");
		return false;
	}
	m_event_fd = eventfd(0, 0);
	// Start the timerfd
	m_timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	struct itimerspec spec = {{m_cfg.real_proc_scan_period, 0}, {m_cfg.real_proc_scan_period, 0}};
	timerfd_settime(m_timer_fd, 0, &spec, NULL);

	m_async_thread = std::thread(&my_plugin::async_thread_loop, this, std::move(f->new_handler()));

	SPDLOG_DEBUG("starting async thread");
	return true;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept {
	eventfd_write(m_event_fd, 1);
	m_async_thread.join();
	close(m_timer_fd);
	close(m_event_fd);
	close(m_fuse_fd);

	free(m_fuse_buf.mem);
	fuse_unmount(m_fuse_handler);
	fuse_destroy(m_fuse_handler);
	fuse_opt_free_args(&m_fuse_args);
	std::filesystem::remove(m_cfg.fs_root.c_str());
	SPDLOG_DEBUG("joined the async thread");
	return true;
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
