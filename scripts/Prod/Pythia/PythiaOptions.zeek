
type OptionKey: record {
key: string;
};

type OptionValue: record {
value: string;

};

global pythia_options: table[string] of OptionValue = table();
global pythia_mode: string ="sensor" &redef;
global pythia_summary_path: string ="/var/db/pythia_summary" &redef;
global pythia_detail_path: string ="/var/db/pythia" &redef;

event zeek_init() 
    {

    Input::add_table([$source="config.file", $name="pythia_options",
                      $idx=OptionKey, $val=OptionValue, $destination=pythia_options]);
    Input::remove("pythia_options");
    }


event Input::end_of_data(name: string, source: string) &priority=6{
    print(pythia_options);

    if (pythia_mode == "pcap")
    {
        pythia_detail_path = pythia_options["pcap_path"]$value + "pythia_pcap";
        pythia_summary_path = pythia_options["pcap_path"]$value + "pythia_summary_pcap";
        print(pythia_detail_path);
    }
    else {
        pythia_detail_path = pythia_options["sensor_path"]$value + "pythia";
        pythia_summary_path = pythia_options["sensor_path"]$value + "pythia_summary";
    }
	print("TEEEEST" + pythia_detail_path + pythia_summary_path);
}
