#include "plugin.h"
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/poll.h>

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

void generate_async_event(const char *json, bool added) {
	falcosecurity::events::asyncevent_e_encoder enc;
	enc.set_tid(1);
	std::string msg = json;
	enc.set_name(ASYNC_EVENT_NAME);
	enc.set_data((void *)msg.c_str(), msg.size() + 1);

	//  enc.encode(s_async_handler->writer());
	// s_async_handler->push();
}

static void *fuse_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
	(void)conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static int fuse_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	(void)fi;
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));

	return res;
}

static int fuse_readdir(const char *path,
                        void *buf,
                        fuse_fill_dir_t filler,
                        off_t offset,
                        struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
	(void)offset;
	(void)fi;
	(void)flags;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	return 0;
}

static int fuse_open(const char *path, struct fuse_file_info *fi) {
	if((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int fuse_read(const char *path,
                     char *buf,
                     size_t size,
                     off_t offset,
                     struct fuse_file_info *fi) {
	size_t len;
	(void)fi;

	return size;
}

static constexpr struct fuse_operations ops = {
        .getattr = fuse_getattr,
        .open = fuse_open,
        .read = fuse_read,
        .readdir = fuse_readdir,
        .init = fuse_init,
};

void my_plugin::async_thread_loop(std::unique_ptr<falcosecurity::async_event_handler> h,
                                  struct fuse *fuse_handler,
                                  int fuse_fd,
                                  int event_fd) noexcept {
	struct pollfd fds[2];
	fds[POLL_FD_FUSE].fd = fuse_fd;
	fds[POLL_FD_FUSE].events = POLLIN;
	fds[POLL_FD_EVENTFD].fd = event_fd;
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
				struct fuse_session *sess = fuse_get_session(fuse_handler);
				int ret = fuse_session_receive_buf(sess, &m_fuse_buf);
				if(ret > 0) {
					fuse_session_process_buf(sess, &m_fuse_buf);
				}
			}
			// Process eventfd exit request
			if(fds[POLL_FD_EVENTFD].revents & POLLIN) {
				uint64_t tt;
				eventfd_read(event_fd, &tt);
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
	fuse_opt_add_arg(&m_fuse_args, PLUGIN_NAME);
	// New handler to generate async event to request fuseFS refreshes
	m_fuse_handler = fuse_new(&m_fuse_args, &ops, sizeof(ops), nullptr);
	auto ret = fuse_mount(m_fuse_handler, m_cfg.fs_root.c_str());
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

	m_async_thread = std::thread(&my_plugin::async_thread_loop,
	                             this,
	                             std::move(f->new_handler()),
	                             m_fuse_handler,
	                             m_fuse_fd,
	                             m_event_fd);

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
	SPDLOG_DEBUG("joined the async thread");
	return true;
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
