@load base/frameworks/sumstats
@load ./summary_scripts/RespHostTopK
@load ./summary_scripts/OriginHostTopK
@load ./summary_scripts/RespPortTopK
@load ./summary_scripts/IPBytesSum
@load ./summary_scripts/ServiceSum
@load ./summary_scripts/ProtoSum
@load ./summary_scripts/ConnectionSum
@load ./summary_scripts/DnsTopK
@load ./summary_scripts/RespPOISum



global portsOfInterest: set[port] = {10/tcp, 21/tcp, 22/tcp, 23/tcp, 25/tcp, 80/tcp, 110/tcp, 139/tcp, 443/tcp, 445/tcp, 3389/tcp, 10/udp, 53/udp, 67/udp, 123/udp, 135/udp, 137/udp, 138/udp, 161/udp, 445/udp, 631/udp, 1434/udp };

event connection_state_remove(c: connection) &priority = 0
    {
    

    SumStats::observe("resp_host",[],SumStats::Observation($str=cat(c$id$resp_h)));
    SumStats::observe("origin_host",[],SumStats::Observation($str=cat(c$id$orig_h)));
    SumStats::observe("resp_port",[],SumStats::Observation($str=cat(c$id$resp_p)));
    SumStats::observe("connection",[],SumStats::Observation($str=cat(c$id)));
    SumStats::observe("ip_bytes",SumStats::Key($str="orig"),SumStats::Observation($num=c$orig$num_bytes_ip));
    SumStats::observe("ip_bytes",SumStats::Key($str="resp"),SumStats::Observation($num=c$resp$num_bytes_ip));
	
    SumStats::observe("proto",SumStats::Key($str=cat(c$conn$proto)),SumStats::Observation($num=1));

    if(c$conn?$service)
    {
	    SumStats::observe("service",SumStats::Key($str=cat(c$conn$service)),SumStats::Observation($num=1));
	}
	else {
		SumStats::observe("service",SumStats::Key($str=" -"),SumStats::Observation($num=1));
	}

	if (c$id$resp_p in portsOfInterest)  
		{
			SumStats::observe("resp_poi",SumStats::Key($str=cat(c$id$resp_p)),SumStats::Observation($num=1));
		}

    }


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count){
    if (query != "")
    {
        SumStats::observe("dns_query",[],SumStats::Observation($str=query));
    }
}

event zeek_init() {
    local rDNSQuery = SumStats::Reducer($stream="dns_query",$apply=set(SumStats::TOPK));
    local rRespHost = SumStats::Reducer($stream="resp_host",$apply=set(SumStats::TOPK));
	local rOriginHost = SumStats::Reducer($stream="origin_host",$apply=set(SumStats::TOPK));
	local rRespPort = SumStats::Reducer($stream="resp_port",$apply=set(SumStats::TOPK));
    local rIPBytes = SumStats::Reducer($stream="ip_bytes",$apply=set(SumStats::SUM));
    local rProto = SumStats::Reducer($stream="proto",$apply=set(SumStats::SUM));
	local rService = SumStats::Reducer($stream="service",$apply=set(SumStats::SUM));
    local rRespPOI = SumStats::Reducer($stream="resp_poi",$apply=set(SumStats::SUM));
	local rConn = SumStats::Reducer($stream="connection",$apply=set(SumStats::SUM));

        SumStats::create([	$name = "top k dns queries",
                    $epoch = 1hrs,
                    $reducers = set(rDNSQuery),
                    $epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
                    
                    local r = result["dns_query"];
                    local s: vector of SumStats::Observation;
                    s = topk_get_top(r$topk,10);
                                        
                        for ( i in s )
                        {
                        if ( i == 10 )
                            break;
                        
                        local query: string = s[i]$str;
                		Log::write(DnsTopK::LOG, [$ts=ts, $name=query,$counter=topk_count(r$topk,s[i])]);

                		}

                		}]);


    				
        	SumStats::create([	$name = "top k resp host",
						$epoch = 1hrs,
						$reducers = set(rRespHost),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
						
						local r = result["resp_host"];
						local s: vector of SumStats::Observation;
						s = topk_get_top(r$topk,10);
												
						    for ( i in s )
                            {
                            if ( i == 10 )
                                break;
							local host: addr = to_addr(s[i]$str);
                		
                        Log::write(RespHostTopK::LOG, [$ts=ts, $name=host,$counter=topk_count(r$topk,s[i])]);


							}
					}]);			

       	SumStats::create([	$name = "top k origin host",
						$epoch = 1hrs,
						$reducers = set(rOriginHost),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
						
						local r = result["origin_host"];
						local s: vector of SumStats::Observation;
						s = topk_get_top(r$topk,10);						
						    for ( i in s )
                            {
                            if ( i == 10 )
                                break;
							local host: addr = to_addr(s[i]$str);
                		
                        Log::write(OriginHostTopK::LOG, [$ts=ts, $name=host,$counter=topk_count(r$topk,s[i])]);

							}
					}]);			

	SumStats::create([	$name = "top k resp port",
						$epoch = 1hrs,
						$reducers = set(rRespPort),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
						local r = result["resp_port"];
						local s: vector of SumStats::Observation;
						s = topk_get_top(r$topk,10);
						    for ( i in s )
                            {
                            if ( i == 10 )
                                break;
							local proto: string = split_string(s[i]$str,/\//)[1];
							local resp_port: port = to_port(s[i]$str);
                            Log::write(RespPortTopK::LOG, [$ts=ts, $resp_p=resp_port,$proto=proto, $counter=topk_count(r$topk,s[i])]);
                            }
                   
					}]);


	SumStats::create([	$name = "sum IP bytes",
						$epoch = 1hrs,
						$reducers = set(rIPBytes),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
						local r = result["ip_bytes"];
						Log::write(IPBytesSum::LOG, [$ts=ts, $name=key$str ,$counter=double_to_count(r$sum/1000)]);
						}]);
						

	SumStats::create([	$name = "sum protocol types",
						$epoch = 1hrs,
						$reducers = set(rProto),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
						local r = result["proto"];
			            Log::write(ProtoSum::LOG, [$ts=ts, $name=key$str ,$counter=r$num]);
						}]);

	SumStats::create([	$name = "connection count",
						$epoch = 1hrs,
						$reducers = set(rConn),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
						local r = result["connection"];
			            Log::write(ConnectionSum::LOG, [$ts=ts ,$counter=r$num]);
						}]);

		SumStats::create([	$name = "sum service types",
						$epoch = 1hrs,
						$reducers = set(rService),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
				    	local r = result["service"];
			            Log::write(ServiceSum::LOG, [$ts=ts, $name=key$str ,$counter=r$num]);
							}]);

		SumStats::create([	$name = "sum poi ",
						$epoch = 1hrs,
						$reducers = set(rRespPOI),
						$epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = {
				    	local r = result["resp_poi"];
						local proto : string = split_string(key$str,/\//)[1];
						local resp_p: port = to_port(key$str);
			            Log::write(RespPOISum::LOG, [$ts=ts, $resp_p=resp_p,$proto=proto ,$counter=r$num]);
							}]);
	
	
	
	
}
