module Bacnet;

export {
    redef enum Log::ID += { LOG_BACNET };

    ###############################################################################################
    ################################  BACnet_Header -> bacnet.log  ################################
    ###############################################################################################
    type BACnet_Header: record {
        ts                      : time             &log &optional;   # Timestamp of when the request started.
        uid                     : string           &log &optional;   # Zeek unique ID for connection
        id                      : conn_id          &log &optional;   # Zeek connection struct (addresses and ports)
        proto                   : transport_proto  &log &optional;   # The transport layer protocol of the connection
        pdu_service             : string           &log &optional;   # Name of Protocol Data Unit service
        pdu_type                : string           &log &optional;   # APDU type (see apdu_types)
        obj_type                : string           &log &optional;   # BACnetObjectIdentifier object (see object_types)
		number                  : int              &log &optional;
		ts_end                  : time             &log &optional;
    };

    global log_bacnet: event(rec: BACnet_Header);

    type AggregationData: record {
        uid                     : string            &log;
        id                      : conn_id           &log;
        proto                   : transport_proto   &log;
        pdu_service             : string            &log;
        pdu_type                : string            &log;
        obj_type                : string            &log;
	};

    type Ts_num: record {
		ts_s:			time &log;
		num: 			int &log;
		ts_e: 			time &log &optional;
	};

    function insert_log(res_aggregationData: table[AggregationData] of Ts_num, idx: AggregationData): interval
	{
	local info_insert: BACnet_Header = [];
	info_insert$ts = res_aggregationData[idx]$ts_s;
	info_insert$uid = idx$uid;
	info_insert$id = idx$id;
    	info_insert$proto = idx$proto;
    	info_insert$pdu_service = idx$pdu_service;
    	info_insert$pdu_type  = idx$pdu_type;
    	info_insert$obj_type  = idx$obj_type;
    	if ( res_aggregationData[idx]?$num ){
		info_insert$number = res_aggregationData[idx]$num;
	}
	if ( res_aggregationData[idx]?$ts_e ){
		info_insert$ts_end = res_aggregationData[idx]$ts_e;
	}

	Log::write(LOG_BACNET, info_insert);
	return 0secs;
	}

    global res_aggregationData: table[AggregationData] of Ts_num &create_expire=60sec &expire_func=insert_log;
}

## Defines BACnet Ports
const ports = { 47808/udp };
redef likely_server_ports += { ports };
redef record connection += {
	Bacnet: BACnet_Header &optional;
};

###################################################################################################
###### Defines Log Streams for bacnet.log
###################################################################################################
event zeek_init() &priority=5{

    Log::create_stream(Bacnet::LOG_BACNET, [$columns=BACnet_Header,
                                            $ev=log_bacnet,
                                            $path="bacnet"]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_BACNET, ports);
}

###################################################################################################
###### Ensure that conn.log:service is set if it has not already been
###################################################################################################
function set_service(c: connection) {
  if ((!c?$service) || (|c$service| == 0)){
    add c$service["bacnet"];
    }
}

function create_aggregationData(bacnet_log: BACnet_Header): AggregationData
	{
	local aggregationData: AggregationData;
	aggregationData$uid = bacnet_log$uid;
    	aggregationData$id = bacnet_log$id;
   	aggregationData$proto = bacnet_log$proto;
    	aggregationData$pdu_service = bacnet_log$pdu_service;
    	aggregationData$pdu_type  = bacnet_log$pdu_type;
    	aggregationData$obj_type  = bacnet_log$obj_type;

	return aggregationData;
	}

function insert_res_aggregationData(aggregationData: AggregationData, bacnet_log: BACnet_Header): string
	{
		if (aggregationData in res_aggregationData){
			res_aggregationData[aggregationData]$num = res_aggregationData[aggregationData]$num + 1;
			res_aggregationData[aggregationData]$ts_e = bacnet_log$ts;
            if (res_aggregationData[aggregationData]$ts_s == res_aggregationData[aggregationData]$ts_e)
            {
               res_aggregationData[aggregationData]$num = 1;
            }
		} else {
			res_aggregationData[aggregationData] = [$ts_s = bacnet_log$ts, $num = 1, $ts_e = bacnet_log$ts];
		}

        return "done";
	}

global last_ts: time = network_time();
###################################################################################################
###### Defines logging of bacnet_apdu_header event -> bacnet.log
###################################################################################################
event bacnet_apdu_header(c: connection,
                         is_orig: bool,
                         bvlc_function: count,
                         pdu_type: count,
                         pdu_service: count,
                         invoke_id: count,
                         result_code: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_type = "";
    if(pdu_type in apdu_types){
        bacnet_log$pdu_type = apdu_types[pdu_type];
    }
    bacnet_log$pdu_service = "";
    bacnet_log$obj_type = "";
    switch(pdu_type){
        case 5:
            fallthrough;
        case 0:
            fallthrough;
        case 2:
            fallthrough;
        case 3:
            bacnet_log$pdu_service = confirmed_service_choice[pdu_service];
            if(pdu_type == 0 && (pdu_service == 6 || pdu_service == 7)){
                bacnet_log$obj_type = "file";
            }
            break;
        case 1:
            bacnet_log$pdu_service = unconfirmed_service_choice[pdu_service];
            break;
        default:
            break;
    }

    if(bacnet_log$ts == last_ts){
        if(bacnet_log$obj_type != ""){
            aggregationData = create_aggregationData(bacnet_log);
            insert_res_aggregationData(aggregationData, bacnet_log);
            c$Bacnet = bacnet_log;
        }
    }
    if(bacnet_log$ts != last_ts){
            aggregationData = create_aggregationData(bacnet_log);
            insert_res_aggregationData(aggregationData, bacnet_log);
            c$Bacnet = bacnet_log;
    }
}

###################################################################################################
###### Defines logging of bacnet_npdu_header event -> bacnet.log
###################################################################################################
event bacnet_npdu_header(c: connection,
                         is_orig: bool,
                         bvlc_function: count,
                         npdu_message_type: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = npdu_message_types[npdu_message_type];
    bacnet_log$pdu_type = "NPDU";
    bacnet_log$obj_type = "";

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

###################################################################################################
###### Defines logging of bacnet_i_am event -> bacnet.log
###################################################################################################
event bacnet_i_am(c: connection,
                  is_orig: bool,
                  object_type: count,
                  instance_number: count,
                  max_apdu: count,
                  segmentation: count,
                  vendor_id: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = "i_am";
    bacnet_log$pdu_type = "UnconfirmedRequest";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

###################################################################################################
###### Defines logging of bacnet_who_has event -> bacnet.log
###################################################################################################
event bacnet_who_has(c: connection,
                     is_orig: bool,
                     low_limit: count,
                     high_limit: count,
                     object_type: count,
                     instance_number: count,
                     object_name: string){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = "who_has";
    bacnet_log$pdu_type = "UnconfirmedRequest";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }else
    {
        bacnet_log$obj_type = "";
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

###################################################################################################
###### Defines logging of bacnet_i_have event -> bacnet.log
###################################################################################################
event bacnet_i_have(c: connection,
                    is_orig: bool,
                    device_object_type: count,
                    device_instance_num: count,
                    object_object_type: count,
                    object_instance_num: count,
                    object_name: string){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = "i_have";
    bacnet_log$pdu_type = "UnconfirmedRequest";
    if(object_object_type in object_types){
        bacnet_log$obj_type = object_types[object_object_type];
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

###################################################################################################
###### Defines logging of bacnet_read_property event -> bacnet.log
###################################################################################################
event bacnet_read_property(c: connection,
                           is_orig: bool,
                           invoke_id: count,
                           pdu_service: string,
                           object_type: count,
                           instance_number: count,
                           property_identifier: count,
                           property_array_index: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    if(pdu_service == "read-property-request"){
        bacnet_log$pdu_service = "read_property";
    }
    if(pdu_service == "read-property-multiple-request"){
        bacnet_log$pdu_service = "read_property_multiple";
    }
    bacnet_log$pdu_type = "ConfirmedRequest";
    bacnet_log$obj_type = "";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

###################################################################################################
###### Defines logging of bacnet_read_property_ack event -> bacnet.log
###################################################################################################
event bacnet_read_property_ack(c: connection,
                               is_orig: bool,
                               invoke_id: count,
                               pdu_service: string,
                               object_type: count,
                               instance_number: count,
                               property_identifier: count,
                               property_array_index: count,
                               property_value: string){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    if(pdu_service == "read-property-ack"){
        bacnet_log$pdu_service = "read_property";
    }
    if(pdu_service == "read-property-multiple-ack"){
        bacnet_log$pdu_service = "read_property_multiple";
    }
    bacnet_log$pdu_type = "ComplexAck";
    bacnet_log$obj_type = "";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

##################################################################################################
###### Defines logging of bacnet_write_property event -> bacnet.log
##################################################################################################
event bacnet_write_property(c: connection,
                            is_orig: bool,
                            invoke_id: count,
                            object_type: count,
                            instance_number: count,
                            property_identifier: count,
                            property_array_index: count,
                            priority: count,
                            property_value: string){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = "write_property";
    bacnet_log$pdu_type = "ConfirmedRequest";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }else
    {
        bacnet_log$obj_type = "";
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}

##################################################################################################
###### Defines logging of bacnet_read_range event -> bacnet.log
##################################################################################################
event bacnet_read_range(c: connection,
                        is_orig: bool,
                        invoke_id: count,
                        object_type: count,
                        instance_number: count,
                        property_identifier: count,
                        property_array_index: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = "read_range";
    bacnet_log$pdu_type = "ConfirmedRequest";
    bacnet_log$obj_type = "";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}
##################################################################################################
###### Defines logging of bacnet_read_range event -> bacnet.log
##################################################################################################
event bacnet_read_range_ack(c: connection,
                            is_orig: bool,
                            invoke_id: count,
                            object_type: count,
                            instance_number: count,
                            property_identifier: count,
                            property_array_index: count,
                            result_flags: count,
                            item_count: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    local aggregationData: AggregationData;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    local p = get_port_transport_proto(c$id$resp_p);
    bacnet_log$proto = p;

    bacnet_log$pdu_service = "read_range";
    bacnet_log$pdu_type = "ComplexAck";
    bacnet_log$obj_type = "";
    if(object_type in object_types){
        bacnet_log$obj_type = object_types[object_type];
    }

    last_ts = bacnet_log$ts;

    aggregationData = create_aggregationData(bacnet_log);
    insert_res_aggregationData(aggregationData, bacnet_log);
    c$Bacnet = bacnet_log;
}


# 集約 local debug用
event zeek_done(){
	for ( i in res_aggregationData ){
		local bacnet_log: BACnet_Header = [];
		bacnet_log$ts = res_aggregationData[i]$ts_s;
		bacnet_log$uid = i$uid;
        bacnet_log$id = i$id;
        bacnet_log$proto = i$proto;
        bacnet_log$pdu_service = i$pdu_service;
        bacnet_log$pdu_type  = i$pdu_type;
        bacnet_log$obj_type  = i$obj_type;

		if ( res_aggregationData[i]?$num ){
			bacnet_log$number = res_aggregationData[i]$num;
		}
        if ( res_aggregationData[i]?$ts_e ){
			bacnet_log$ts_end = res_aggregationData[i]$ts_e;
		}

		Log::write(LOG_BACNET, bacnet_log);
	}
}
