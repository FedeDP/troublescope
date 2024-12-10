#include "plugin.h"

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
    enc.set_data((void*)msg.c_str(), msg.size() + 1);

    enc.encode(s_async_handler->writer());
    s_async_handler->push();
}

// We need this API to start the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::start_async_events(
        std::shared_ptr<falcosecurity::async_event_handler_factory> f) {
    s_async_handler = std::move(f->new_handler());

    SPDLOG_DEBUG("starting async worker");
    // TODO? do we need it?
    return true;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept {
    SPDLOG_DEBUG("stopping async worker");
    // TODO?
    return true;
}

FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
