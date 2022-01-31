
# Adds new filter with subset of conn, notice and dns for streams
event zeek_init() &priority=4
{
Log::add_filter(Conn::LOG,[$name="conn_filter", $include=set("ts","uid","id.orig_h", "id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_ip_bytes","resp_ip_bytes"),$path=pythia_detail_path, $config=table(["tablename"]="conn"),$writer=Log::WRITER_SQLITE]);

Log::add_filter(Notice::LOG,[$name="notice_filter", $include=set("ts","uid","note","msg"), $path=pythia_detail_path, $config=table(["tablename"]="notice"),$writer=Log::WRITER_SQLITE]);

Log::add_filter(DNS::LOG,[$name="dns_filter", $include=set("uid","query","answers","qtype_name","rcode_name"), $path=pythia_detail_path, $config=table(["tablename"]="dns"),$writer=Log::WRITER_SQLITE]);

}


