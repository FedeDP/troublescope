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

#include "consts.h"
#include "plugin_config.h"
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>  // to get fuse fd to process events internally

class my_plugin {
public:
	//////////////////////////
	// General plugin API
	//////////////////////////

	virtual ~my_plugin() = default;

	std::string get_name();
	std::string get_version();
	std::string get_description();
	std::string get_contact();
	std::string get_required_api_version();
	std::string get_last_error();
	void destroy();
	falcosecurity::init_schema get_init_schema();
	void parse_init_config(nlohmann::json &config_json);
	bool init(falcosecurity::init_input &in);
	const std::vector<falcosecurity::metric> &get_metrics();

	//////////////////////////
	// Async capability
	//////////////////////////

	std::vector<std::string> get_async_events();
	std::vector<std::string> get_async_event_sources();
	bool start_async_events(std::shared_ptr<falcosecurity::async_event_handler_factory> f);
	bool stop_async_events() noexcept;
	void async_thread_loop(std::unique_ptr<falcosecurity::async_event_handler> h,
	                       struct fuse *fuse_handler,
	                       int fuse_fd,
	                       int event_fd) noexcept;

	//////////////////////////
	// Parse capability
	//////////////////////////

	std::vector<std::string> get_parse_event_sources();
	std::vector<falcosecurity::event_type> get_parse_event_types();
	bool parse_new_process_event(const falcosecurity::parse_event_input &in);
	bool parse_event(const falcosecurity::parse_event_input &in);

	//////////////////////////
	// Listening capability
	//////////////////////////
	bool capture_open(const falcosecurity::capture_listen_input &in);
	bool capture_close(const falcosecurity::capture_listen_input &in);

private:
	// Async thread - fuseFS stuff
	std::thread m_async_thread;
	int m_event_fd = -1;
	int m_fuse_fd = -1;
	struct fuse_buf m_fuse_buf;
	struct fuse *m_fuse_handler;
	struct fuse_args m_fuse_args;

	std::vector<falcosecurity::metric> m_metrics;

	PluginConfig m_cfg;

	// Last error of the plugin
	std::string m_lasterr;
	// Accessor to the thread table
	falcosecurity::table m_threads_table;
	// Accessors to the thread table "pidns_init_start_ts" field
	falcosecurity::table_field m_threads_field_pidns_init_start_ts;
	// Accessors to the thread table "category" field
	falcosecurity::table_field m_threads_field_category;
	// Accessors to the thread table "vpid" field
	falcosecurity::table_field m_threads_field_vpid;
	// Accessors to the thread table "ptid" field
	falcosecurity::table_field m_threads_field_tid;
	falcosecurity::table_field m_threads_field_comm;

	// Accessors to the thread table "cgroups" table
	falcosecurity::table_field m_threads_field_cgroups;
	// Accessors to the thread table "cgroups" "second" field, ie: the cgroups
	// path
	falcosecurity::table_field m_cgroups_field_second;
	// Accessors to the thread table "container_id" foreign key field
	falcosecurity::table_field m_container_id_field;
};
