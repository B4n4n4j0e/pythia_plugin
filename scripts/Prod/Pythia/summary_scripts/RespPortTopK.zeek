module RespPortTopK;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;
        resp_p: port     &log;
        proto: string &log;
        counter: count &log &default=0;
    };
    

event Input::end_of_data(name: string, source: string)
    {
    local filter : Log::Filter = 
    [
        $name="sqlite",
        $path=pythia_summary_path,
        $config=table(["tablename"]="resp_port_top_k"),
        $writer=Log::WRITER_SQLITE
    ];
    Log::create_stream(RespPortTopK::LOG, [$columns=Info, $path="resp_port_top_k"]);
    Log::add_filter(RespPortTopK::LOG, filter);
    }
}
