

#redef Log::default_field_name_map = {
#	["query"]="query_text"
#};

event Input::end_of_data(name: string, source: string)
{
print(pythia_detail_path + "THIS IS DETAIL");
Log::remove_default_filter(Conn::LOG);
Log::remove_default_filter(Notice::LOG);
Log::remove_default_filter(DNS::LOG);
Log::remove_default_filter(Weird::LOG);
Log::remove_default_filter(Files::LOG);
Log::remove_default_filter(NTP::LOG);
Log::remove_default_filter(SSL::LOG);
Log::remove_default_filter(HTTP::LOG);
Log::remove_default_filter(X509::LOG);
Log::remove_default_filter(Stats::LOG);
Log::remove_default_filter(Software::LOG);
Log::remove_default_filter(DHCP::LOG);
#Log::remove_default_filter(ConnSummary::Log);
Log::remove_default_filter(CaptureLoss::LOG);

Log::add_filter(Conn::LOG,[$name="conn_filter", $include=set("ts","uid","id.orig_h", "id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_ip_bytes","resp_ip_bytes"),$path=pythia_detail_path, $config=table(["tablename"]="conn"),$writer=Log::WRITER_SQLITE]);

Log::add_filter(Notice::LOG,[$name="notice_filter", $include=set("ts","uid","note","msg"), $path=pythia_detail_path, $config=table(["tablename"]="notice"),$writer=Log::WRITER_SQLITE]);

Log::add_filter(Weird::LOG,[$name="weird_filter", $include=set("ts","uid","name"), $path=pythia_detail_path, $config=table(["tablename"]="weird"),$writer=Log::WRITER_SQLITE]);

Log::add_filter(DNS::LOG,[$name="dns_filter", $include=set("uid","query","answers","qtype_name","rcode_name"), $path=pythia_detail_path, $config=table(["tablename"]="dns"),$writer=Log::WRITER_SQLITE]);

}
