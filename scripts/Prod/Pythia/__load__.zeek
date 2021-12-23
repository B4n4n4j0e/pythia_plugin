#
# This is processed when a user explicitly loads the plugin's script module
# through `@load <plugin-namespace>/<plugin-name>`. Include code here that
# should execute at that point. This is the most common entry point to
# your plugin's accompanying scripts.
#
@load ./PythiaOptions
@if ( pythia_options["sensor_path"]value == "/var/db/pythia" )
    print "version 2 detected";
@endif

@load ./PythiaDetail
@load ./PythiaSummary 

bb