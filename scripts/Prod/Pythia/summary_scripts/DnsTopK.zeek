module DnsTopK;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;
        name: string     &log;
        counter: count &log &default=0;
    };
    

event Input::end_of_data(name: string, source: string)
    {
    print("THIS IS THE PATH (SUMMARY):" + pythia_summary_path);
    local filter : Log::Filter = 
    [
        $name="sqlite",
        $path=pythia_summary_path,
        $config=table(["tablename"]="dns_top_k"),
        $writer=Log::WRITER_SQLITE
    ];
    Log::create_stream(DnsTopK::LOG, [$columns=Info, $path="dns_top_k"]);
    Log::add_filter(DnsTopK::LOG, filter);
    }
}
