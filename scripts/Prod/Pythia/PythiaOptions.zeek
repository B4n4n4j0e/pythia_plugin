#get variables for configuration from environment variables

global pythia_mode: string = getenv("PYTHIA_ZEEK_MODE") &redef;
global pythia_config: string = getenv("PYTHIA_CONFIG") &redef;
global pythia_pcap_config: string = getenv("PYTHIA_PCAP_CONFIG") &redef;
global pythia_summary_path: string =getenv("PYTHIA_PATH") &redef;
global pythia_detail_path: string = getenv("PYTHIA_PATH") &redef;
global pythia_summary_pcap_path: string =getenv("PYTHIA_PCAP_PATH") &redef;
global pythia_detail_pcap_path: string = getenv("PYTHIA_PCAP_PATH") &redef;


#sets path for log writes depending on pythia_mode variable
event zeek_init() &priority=8
    {
    if (pythia_mode == "pcap")
    {
        pythia_detail_path = getenv("PYTHIA_PCAP_PATH") + "/pythia_pcap";
        pythia_summary_path = getenv("PYTHIA_PCAP_PATH") + "/pythia_summary_pcap";
 
    }
    else {
        pythia_detail_path = pythia_detail_path + "/pythia";
        pythia_summary_path = pythia_summary_path + "/pythia_summary";
    }

}
