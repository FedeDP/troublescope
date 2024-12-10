#include "plugin.h"
#define FUSE_USE_VERSION 31
#include <fcntl.h>
#include <fuse.h>

//////////////////////////
// Async capability
//////////////////////////

static std::unique_ptr<falcosecurity::async_event_handler> s_async_handler;

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

  enc.encode(s_async_handler->writer());
  s_async_handler->push();
}

static void *hello_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  (void)conn;
  cfg->kernel_cache = 1;
  return NULL;
}

static int hello_getattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
  (void)fi;
  int res = 0;

  memset(stbuf, 0, sizeof(struct stat));

  return res;
}

static int hello_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
  (void)offset;
  (void)fi;
  (void)flags;

  if (strcmp(path, "/") != 0)
    return -ENOENT;

  return 0;
}

static int hello_open(const char *path, struct fuse_file_info *fi) {
  if ((fi->flags & O_ACCMODE) != O_RDONLY)
    return -EACCES;

  return 0;
}

static int hello_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
  size_t len;
  (void)fi;

  return size;
}

static constexpr struct fuse_operations hello_oper = {
    .getattr = hello_getattr,
    .open = hello_open,
    .read = hello_read,
    .readdir = hello_readdir,
    .init = hello_init,
};

void my_plugin::async_thread_loop(
    std::unique_ptr<falcosecurity::async_event_handler> h) noexcept {

  char *argv[] = {"troublescope", "-f", (char *)m_cfg.fs_root.c_str()};
  struct fuse_args args = {3, argv, 0};
  // move on secondary thread
  SPDLOG_INFO("Async thread start");
  fuse_main(args.argc, args.argv, &hello_oper, NULL);
  fuse_opt_free_args(&args);
  SPDLOG_INFO("Async thread terminated");
}

// We need this API to start the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::start_async_events(
    std::shared_ptr<falcosecurity::async_event_handler_factory> f) {
  s_async_handler = std::move(f->new_handler());

  m_async_thread_quit = false;
  m_async_thread = std::thread(&my_plugin::async_thread_loop, this,
                               std::move(f->new_handler()));

  SPDLOG_DEBUG("starting async thread");
  return true;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept {
  {
    std::unique_lock l(m_mu);
    m_async_thread_quit = true;
    m_cv.notify_one();
    // Release the lock
  }

  if (m_async_thread.joinable()) {
    m_async_thread.join();
    SPDLOG_DEBUG("joined the async thread");
  }
  return true;
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
