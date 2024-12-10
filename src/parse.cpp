#include "plugin.h"

//////////////////////////
// Parse capability
//////////////////////////

struct sinsp_param {
    uint32_t param_len;
    uint8_t* param_pointer;
};

// Obtain a param from a sinsp event
template <const bool LargePayload=false, typename T=std::conditional_t<LargePayload, uint32_t*, uint16_t*>>
static inline sinsp_param get_syscall_evt_param(void* evt, uint32_t num_param)
{
    uint32_t dataoffset = 0;
    // pointer to the lengths array inside the event.
    auto len = (T)((uint8_t*)evt + sizeof(falcosecurity::_internal::ss_plugin_event));
    for(uint32_t j = 0; j < num_param; j++)
    {
        // sum lengths of the previous params.
        dataoffset += len[j];
    }
    return {.param_len = len[num_param],
            .param_pointer =
            ((uint8_t*)&len
            [((falcosecurity::_internal::ss_plugin_event*)evt)
                            ->nparams]) +
            dataoffset};
}

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

bool my_plugin::parse_new_process_event(
        const falcosecurity::parse_event_input& in) {
    // get tid
    auto thread_id = in.get_event_reader().get_tid();

    // compute container_id from tid->cgroups
    auto& tr = in.get_table_reader();

    // retrieve the thread entry associated with this thread id
    try {
    	auto thread_entry = m_threads_table.get_entry(tr, thread_id);

        // TODO
    	return true;
    } catch (falcosecurity::plugin_exception &e) {
      	SPDLOG_ERROR("cannot attach fuseFS entry to new process event for the thread id '{}': {}",
                     thread_id, e.what());
        return false;
    }
}

bool my_plugin::parse_event(const falcosecurity::parse_event_input& in) {
    // NOTE: today in the libs framework, parsing errors are not logged
    auto& evt = in.get_event_reader();

    switch(evt.get_type())
    {
        case PPME_SYSCALL_CLONE_20_X:
        case PPME_SYSCALL_FORK_20_X:
        case PPME_SYSCALL_VFORK_20_X:
        case PPME_SYSCALL_CLONE3_X:
        case PPME_SYSCALL_EXECVE_16_X:
        case PPME_SYSCALL_EXECVE_17_X:
        case PPME_SYSCALL_EXECVE_18_X:
        case PPME_SYSCALL_EXECVE_19_X:
        case PPME_SYSCALL_EXECVEAT_X:
        case PPME_SYSCALL_CHROOT_X:
            return parse_new_process_event(in);
        default:
            SPDLOG_ERROR("received an unknown event type {}",
                         int32_t(evt.get_type()));
            return false;
    }
}

FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);