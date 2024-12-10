/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "plugin.h"
#include "plugin_config_schema.h"

//////////////////////////
// General plugin API
//////////////////////////

std::string my_plugin::get_name() {
	return PLUGIN_NAME;
}

std::string my_plugin::get_version() {
	return PLUGIN_VERSION;
}

std::string my_plugin::get_description() {
	return PLUGIN_DESCRIPTION;
}

std::string my_plugin::get_contact() {
	return PLUGIN_CONTACT;
}

std::string my_plugin::get_required_api_version() {
	return PLUGIN_REQUIRED_API_VERSION;
}

std::string my_plugin::get_last_error() {
	return m_lasterr;
}

void my_plugin::destroy() {
	SPDLOG_DEBUG("detach the plugin");
}

falcosecurity::init_schema my_plugin::get_init_schema() {
	falcosecurity::init_schema init_schema;
	init_schema.schema_type = falcosecurity::init_schema_type::SS_PLUGIN_SCHEMA_JSON;
	init_schema.schema = plugin_schema_string;
	return init_schema;
}

void my_plugin::parse_init_config(nlohmann::json &config_json) {
	m_cfg = config_json.get<PluginConfig>();
	// Verbosity, the default verbosity is already set in the 'init' method
	if(m_cfg.verbosity != "info") {
		// If the user specified a verbosity we override the actual one (`info`)
		spdlog::set_level(spdlog::level::from_str(m_cfg.verbosity));
	}
}

bool my_plugin::init(falcosecurity::init_input &in) {
	using st = falcosecurity::state_value_type;
	auto &t = in.tables();

	// The default logger is already multithread.
	// The initial verbosity is `info`, after parsing the plugin config, this
	// value could change
	spdlog::set_level(spdlog::level::info);

	// Alternatives logs:
	// spdlog::set_pattern("%a %b %d %X %Y: [%l] [container] %v");
	//
	// We use local time like in Falco, not UTC
	spdlog::set_pattern("%c: [%l] [troublescope] %v");

	// This should never happen, the config is validated by the framework
	if(in.get_config().empty()) {
		m_lasterr = "cannot find the init config for the plugin";
		SPDLOG_CRITICAL(m_lasterr);
		return false;
	}

	auto cfg = nlohmann::json::parse(in.get_config());
	parse_init_config(cfg);

	SPDLOG_DEBUG("init the plugin");

	// Remove this log when we reach `1.0.0`
	SPDLOG_WARN(
	        "[EXPERIMENTAL] This plugin is in active development "
	        "and may undergo changes in behavior without prioritizing "
	        "backward compatibility.");

	try {
		m_threads_table = t.get_table(THREAD_TABLE_NAME, st::SS_PLUGIN_ST_INT64);

		// vpid and ptid are used to attach the category field to the thread entry
		m_threads_field_tid =
		        m_threads_table.get_field(t.fields(), TID_FIELD_NAME, st::SS_PLUGIN_ST_INT64);
		m_threads_field_comm =
		        m_threads_table.get_field(t.fields(), COMM_FIELD_NAME, st::SS_PLUGIN_ST_STRING);
		m_threads_field_exe =
		        m_threads_table.get_field(t.fields(), EXE_FIELD_NAME, st::SS_PLUGIN_ST_STRING);
		m_threads_field_cwd =
		        m_threads_table.get_field(t.fields(), CWD_FIELD_NAME, st::SS_PLUGIN_ST_STRING);
		m_threads_field_file_descriptors = m_threads_table.get_field(t.fields(),
		                                                             FILE_DESCRIPTORS_FIELD_NAME,
		                                                             st::SS_PLUGIN_ST_TABLE);
		m_fd_field_name = t.get_subtable_field(m_threads_table,
		                                       m_threads_field_file_descriptors,
		                                       FD_FIELD_NAME,
		                                       st::SS_PLUGIN_ST_STRING);
		m_fd_field_fd = t.get_subtable_field(m_threads_table,
		                                     m_threads_field_file_descriptors,
		                                     FD_FIELD_FD,
		                                     st::SS_PLUGIN_ST_INT64);
	} catch(falcosecurity::plugin_exception e) {
		m_lasterr = std::string("Failed to get a field from the table: ") + e.what();
		SPDLOG_CRITICAL(m_lasterr);
		return false;
	}
	return true;
}

FALCOSECURITY_PLUGIN(my_plugin);
