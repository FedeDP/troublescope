#include "plugin_config.h"
#include <filesystem>

void from_json(const nlohmann::json &j, PluginConfig &cfg) {
	cfg.verbosity = j.value("verbosity", "info");
	cfg.fs_root = j.value("fs_root", "/tmp/troublescope");
	cfg.real_proc_scan_period = j.value("real_proc_scan_period", 30);
	cfg.host_root = j.value("host_root", "");
}
