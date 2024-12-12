#pragma once

#include <nlohmann/json.hpp>
#include "macros.h"

struct PluginConfig {
	std::string verbosity;
	int real_proc_scan_period;  // seconds
	std::string fs_root;        // root of fuseFS
	std::string host_root;

	PluginConfig() {
		real_proc_scan_period = 30;
		fs_root = "/tmp/troublescope";
		verbosity = "info";
	}
};

/* Nlhomann adapters (implemented by plugin_config.cpp) */

// from_json is used by parse_init_config() during plugin::init and just parses
// plugin config json string to a structure.
void from_json(const nlohmann::json &j, PluginConfig &cfg);
