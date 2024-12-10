#include "plugin.h"
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/poll.h>

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

static void *hello_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
	(void)conn;
	cfg->kernel_cache = 1;
	return NULL;
}

static int hello_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	(void)fi;
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));

	return res;
}

static int hello_readdir(const char *path,
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

static int hello_open(const char *path, struct fuse_file_info *fi) {
	if((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int hello_read(const char *path,
                      char *buf,
                      size_t size,
                      off_t offset,
                      struct fuse_file_info *fi) {
	size_t len;
	(void)fi;

	return size;
}

static constexpr struct fuse_operations ops = {
        .getattr = hello_getattr,
        .open = hello_open,
        .read = hello_read,
        .readdir = hello_readdir,
        .init = hello_init,
};

void my_plugin::async_thread_loop(std::unique_ptr<falcosecurity::async_event_handler> h,
                                  struct fuse *fuse_handler,
                                  int fuse_fd,
                                  int event_fd) noexcept {
	struct pollfd fds[2];
	fds[0].fd = fuse_fd;
	fds[0].events = POLLIN;
	fds[1].fd = event_fd;
	fds[1].events = POLLIN;

	struct fuse_buf buf;
	while(true) {
		auto ret = poll(fds, std::size(fds), -1);
		switch(ret) {
		case -1:
		case 0:
			break;
		default: {
			if(fds[0].revents & POLLIN) {
				struct fuse_session *sess = fuse_get_session(fuse_handler);
				int ret = fuse_session_receive_buf(sess, &buf);
				if(ret > 0) {
					fuse_session_process_buf(sess, &buf);
				}
			}
			if(fds[1].revents & POLLIN) {
				eventfd_read(event_fd);
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
	struct fuse_args args;
	fuse_opt_add_arg(&args, PLUGIN_NAME);
	// New handler to generate async event to request fuseFS refreshes
	auto fuse_handler = fuse_new(&args, &ops, sizeof(ops), nullptr);
	auto ret = fuse_mount(fuse_handler, m_cfg.fs_root.c_str());
	if(ret != 0) {
		SPDLOG_ERROR("fuse_mount failed: {}", ret);
		return false;
	}
	auto fuse_fd = fuse_session_fd(fuse_get_session(fuse_handler));
	if(fuse_fd < 0) {
		SPDLOG_ERROR("fuse_session_fd failed");
		return false;
	}
	m_event_fd = eventfd(0, 0);

	m_async_thread = std::thread(&my_plugin::async_thread_loop,
	                             this,
	                             std::move(f->new_handler()),
	                             fuse_handler,
	                             fuse_fd,
	                             m_event_fd);

	SPDLOG_DEBUG("starting async thread");
	return true;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept {
	eventfd_write(m_event_fd, 1);
	m_async_thread.join();
	SPDLOG_DEBUG("joined the async thread");
	return true;
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
