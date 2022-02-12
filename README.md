
Prod::Pythia
=================================

# Description
pythia_plugin implements zeek specific configuration to run the Pythia application. See https://github.com/B4n4n4j0e/pythia for more information to Pythia

# Install 
- git clone this repository 
- Change to the pythia_plugin directory
- To build application ```./configure --zeek-dist=/path/to/zeek/dist && make```
- To check if it works ```export ZEEK_PLUGIN_PATH="path/to/pythia_plugin/build"```
    - If ```zeek -N | grep Pythia``` returns information the plugin works
- Don't forget to add the module by inserting ``@load Prod/Pythia`` at the end of local.zeek. 
- For more information see zeek documentation. 