#
# This is processed when a user explicitly loads the plugin's script module
# through `@load <plugin-namespace>/<plugin-name>`. Include code here that
# should execute at that point. This is the most common entry point to
# your plugin's accompanying scripts.
#
@load ./PythiaOptions
@load ./DisableDefaultLogs

#Loads scripts depending on environment variables
@if (pythia_mode == "sensor")
    @if (/:SCAN:/ in pythia_config)
        @load misc/scan
    @endif
    @if(/:TRACEROUTE:/ in pythia_config )
        @load ./test
        @load misc/detect-traceroute
    @endif
    @if (!(/:NOSUMMARY:/ in pythia_config))
        @load ./PythiaSummary 
    @endif
    @if (!(/:NODETAIL:/ in pythia_config))
        @load ./PythiaDetail
    @endif
@else 
    @if (pythia_mode == "pcap")
        @if (/:SCAN:/ in pythia_pcap_config)
            @load misc/scan
        @endif        
        @if(/:TRACEROUTE:/ in pythia_pcap_config)
            @load misc/detect-traceroute
        @endif
        @if (!("/:NOSUMMARY:/" in pythia_pcap_config))
            @load ./PythiaSummary 
        @endif
        @if (!(/:NODETAIL:/ in pythia_pcap_config))
            @load ./PythiaDetail
        @endif
    @endif
@endif 

