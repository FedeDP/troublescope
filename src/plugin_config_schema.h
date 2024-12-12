#pragma once

#define LONG_STRING_CONST(...) #__VA_ARGS__

const char plugin_schema_string[] = LONG_STRING_CONST(

    {
      "$schema" : "http://json-schema.org/draft-04/schema#",
      "required" : [],
      "properties" : {
        "verbosity" : {
          "enum" : [ "trace", "debug", "info", "warning", "error", "critical" ],
          "title" : "The plugin logging verbosity",
          "description" :
              "The verbosity that the plugin will use when printing logs."
        },
        "real_proc_scan_period" : {
          "type" : "integer",
          "title" : "RealProc scan period",
          "description" : "Period in seconds between real proc scans."
        },
        "fs_root" : {
          "type" : "string",
          "title" : "Fs Root",
          "description" : "Root for Fuse FileSystem."
        },
        "host_root": {
          "type" : "string",
          "title" : "Host Root",
          "description" : "Root when mounted within a container volume."
        }
      },
      "additionalProperties" : false,
      "type" : "object"
    }

); // LONG_STRING_CONST macro
