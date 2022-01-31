module OriginHostTopK;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;
        name: addr     &log;
        counter: count &log &default=0;
    };
    
# Defines and applies filter for new stream
event zeek_init() &priority=4
    {
    local filter : Log::Filter = 
    [
        $name="sqlite",
        $path=pythia_summary_path,
        $config=table(["tablename"]="origin_host_top_k"),
        $writer=Log::WRITER_SQLITE
    ];
    Log::create_stream(OriginHostTopK::LOG, [$columns=Info, $path="origin_host_top_k"]);
    Log::add_filter(OriginHostTopK::LOG, filter);
    }
}
