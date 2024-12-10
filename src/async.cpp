#include "plugin.h"
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/poll.h>
#include <filesystem>

#define POLL_FD_FUSE 0
#define POLL_FD_EVENTFD 1

//////////////////////////
// Async capability
//////////////////////////

std::vector<std::string> my_plugin::get_async_events() {
	return ASYNC_EVENT_NAMES;
}

std::vector<std::string> my_plugin::get_async_event_sources() {
	return ASYNC_EVENT_SOURCES;
}

void generate_async_event(const std::unique_ptr<falcosecurity::async_event_handler> &h,
                          const std::string &event_name,
                          int64_t tid,
                          std::string msg) {
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
		stbuf->st_nlink = 0;  // TODO correct value
		return 0;
	}

	int pid;
	char p[32];
	int ret = sscanf(path, "/%d/%s", &pid, p);
	if(ret == 1) {
		// we only matched "/1000"
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 0;  // TODO correct value
		return 0;
	}
	if(ret == 2) {
		// we matched /1000/foo
		if(strcmp(p, "cwd") == 0 || strcmp(p, "exe") == 0) {
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
		auto *ctx = (_fuse_context *)fuse_get_context()->private_data;
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

		if(strcmp(path, "/") == 0) {
			generate_async_event(ctx->async_event_handler, ASYNC_EVENT_ROOT_NAME, pid, "root");
		}

		if(sscanf(path, "/%d", &pid) == 1) {
			generate_async_event(ctx->async_event_handler, ASYNC_EVENT_PID_NAME, pid, "pid");
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

static int fuse_read(const char *path,
                     char *buf,
                     size_t size,
                     off_t offset,
                     struct fuse_file_info *fi) {
	{
		auto *ctx = (struct _fuse_context *)fuse_get_context()->private_data;
		if(ctx == NULL) {
			return -EINVAL;
		}
		if(offset != 0) {
			// Unsupported
			return -EPERM;
		}

		std::unique_lock l(ctx->m_mu);
		ctx->done = false;
		memset(buf, 0, size);
		ctx->buf = buf;
		int pid = 0;
		char entry[32];
		sscanf(path, "/%d/%s", &pid, entry);
		generate_async_event(ctx->async_event_handler, ASYNC_EVENT_ENTRY_NAME, pid, entry);
		ctx->m_cv.wait(l, [ctx] { return ctx->done; });
	}

	size = strlen(buf) + 1;
	return size;
}

static int fuse_readlink(const char *path, char *buf, size_t size) {
	auto *ctx = (struct _fuse_context *)fuse_get_context()->private_data;
	if(ctx == NULL) {
		return -EINVAL;
	}

	std::unique_lock l(ctx->m_mu);
	ctx->done = false;
	memset(buf, 0, size);
	ctx->buf = buf;
	int pid = 0;
	char entry[32];
	sscanf(path, "/%d/%s", &pid, entry);
	generate_async_event(ctx->async_event_handler, ASYNC_EVENT_ENTRY_NAME, pid, entry);
	ctx->m_cv.wait(l, [ctx] { return ctx->done; });
	return 0;
};

static constexpr struct fuse_operations ops = {
        .getattr = fuse_getattr,
        .readlink = fuse_readlink,
        .open = fuse_open,
        .read = fuse_read,
        .readdir = fuse_readdir,
};

void my_plugin::async_thread_loop(std::unique_ptr<falcosecurity::async_event_handler> h) noexcept {
	struct pollfd fds[2];
	fds[POLL_FD_FUSE].fd = m_fuse_fd;
	fds[POLL_FD_FUSE].events = POLLIN;
	fds[POLL_FD_EVENTFD].fd = m_event_fd;
	fds[POLL_FD_EVENTFD].events = POLLIN;

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
				uint64_t tt;
				eventfd_read(m_event_fd, &tt);
				goto exit;
			}
			break;
		}
		}
	}

exit:
	SPDLOG_INFO("Async thread terminated");
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
	m_fuse_context.async_event_handler = f->new_handler();
	m_fuse_handler = fuse_new(&m_fuse_args, &ops, sizeof(ops), &m_fuse_context);
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

	m_async_thread = std::thread(&my_plugin::async_thread_loop, this, std::move(f->new_handler()));

	SPDLOG_DEBUG("starting async thread");
	return true;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept {
	eventfd_write(m_event_fd, 1);
	m_async_thread.join();
	close(m_event_fd);
	close(m_fuse_fd);

	free(m_fuse_buf.mem);
	fuse_unmount(m_fuse_handler);
	fuse_destroy(m_fuse_handler);
	fuse_opt_free_args(&m_fuse_args);
	rmdir(m_cfg.fs_root.c_str());
	SPDLOG_DEBUG("joined the async thread");
	return true;
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
