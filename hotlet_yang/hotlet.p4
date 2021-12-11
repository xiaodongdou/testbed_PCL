/* -*- P4_16 -*- */
//need to handle ARP
#include <core.p4>
#include <tna.p4>

#define Hotlet_ts_thresh  200000
#define message_thresh  1000000
#define sketch_size    65536
#define Hotlet_freq_thresh 30

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
enum bit<16> ether_type_t {
    TPID       = 0x8100,
    IPV4       = 0x0800,
    ARP        = 0x0806,
    CLEAN      = 0x3333
}

enum bit<8>  ip_proto_t {
    ICMP  = 1,
    IGMP  = 2,
    TCP   = 6,
    UDP   = 17
}

type bit<48> mac_addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header vlan_tag_h {
    bit<3>        pcp;
    bit<1>        cfi;
    bit<12>       vid;
    ether_type_t  ether_type;
}

header arp_h {
    bit<16>       htype;
    bit<16>       ptype;
    bit<8>        hlen;
    bit<8>        plen;
    bit<16>       opcode;
    mac_addr_t    hw_src_addr;
    bit<32>       proto_src_addr;
    mac_addr_t    hw_dst_addr;
    bit<32>       proto_dst_addr;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<7>       diffserv;
    bit<1>       res;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    bit<32>      src_addr;
    bit<32>      dst_addr;
}

header icmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header igmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

header mirror_h
{
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
    bit<8> clean_flag;
    bit<16> index;
}

header clean_h
{
    bit<1> detector_flag;
    bit<1> scheduler_flag;
    bit<6> padding;
    bit<16> index;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
  
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h         ethernet;
    clean_h            clean;
    arp_h              arp;
    vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;
    icmp_h             icmp;
    igmp_h             igmp;
    tcp_h              tcp;
    udp_h              udp;
}


    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<32>     flow_id;
    bit<16>     index;
    bit<16>     dynamic_ecmp_port;
    bit<32>     s_d_port;
    bit<32>     freq;
    bit<32>     tstamp;
    bit<16>     static_ecmp_port;
    bit<16>     port_setting;
    bit<16>     final_output_port;
    bit<1>      set_flag;
    bit<1>      schedule_flag;
    mirror_h    mirror;
    MirrorId_t session_id;
}

struct id_freq_pair{
    bit<32>     id;
    bit<32>     freq;
}

struct id_tstamp_pair{
    bit<32>     id;
    bit<32>     tstamp;
}


    /***********************  P A R S E R  **************************/
@pa_atomic("ingress", "meta.tstamp")
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.freq = 0;
        meta.index = 0;
        meta.flow_id = 0;
        transition parse_ethernet; 
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.ARP             :  parse_arp;
            (bit<16>)ether_type_t.CLEAN           :  parse_clean;
            default :  accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition  accept;
    }
    state parse_clean {
        pkt.extract(hdr.clean);
        transition  accept;
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            default: accept;
        }    
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            1 : parse_icmp;
            2 : parse_igmp;
            6 : parse_tcp;
           17 : parse_udp;
            default : accept;
        }    
    }

    state parse_icmp {
        meta.s_d_port = pkt.lookahead<bit<32>>();
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_igmp {
        meta.s_d_port = pkt.lookahead<bit<32>>();
        pkt.extract(hdr.igmp);
        transition accept;  
    }

    state parse_tcp {
        meta.s_d_port = pkt.lookahead<bit<32>>();
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        meta.s_d_port = pkt.lookahead<bit<32>>();
        pkt.extract(hdr.udp);
        transition accept;
    }

}


control Ingress(/* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    CRCPolynomial<bit<32>>(0x04C11DB7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32a;
    CRCPolynomial<bit<32>>(0x741B8CD7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32b;
    CRCPolynomial<bit<32>>(0xDB710641,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32c;
    CRCPolynomial<bit<32>>(0x82608EDB,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32fp;

    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,crc32a) hash_1;
    Hash<bit<2>>(HashAlgorithm_t.CUSTOM,crc32b) hash_dynamic_ecmp;
    Hash<bit<2>>(HashAlgorithm_t.CUSTOM,crc32c) hash_static_ecmp;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM,crc32fp) hash_fp;
    bit<2> dynamic_ecmp = 0;
    bit<2> static_ecmp = 0;
    bit<16> output_port = 0;
    bit<1> hot_flag = 0;
    bit<1> flowlet_flag = 0;
    bit<1> message_flag = 0;
    bit<1> flowlet_flag_sch = 0;
    bit<1> message_flag_sch = 0;
    bit<1> zero_flag = 0;
    bit<1> id_equal_flag = 0;
    bit<1> port_select_flag = 0;
    Register<id_freq_pair, bit<16>>(65536) reg_id_freq;
    RegisterAction<id_freq_pair, bit<16>, bit<32>>(reg_id_freq) first_phase =
    {
    void apply(inout id_freq_pair register_data, out bit<32> result) {
            if (register_data.id == meta.flow_id)
            {
                register_data.freq = register_data.freq + 1;
                result = register_data.freq;
            }
            if (register_data.id != meta.flow_id && register_data.freq != 0)
            {
                register_data.freq = register_data.freq - 1;
            }
            if (register_data.id != meta.flow_id && register_data.freq == 0)
            {
                register_data.id = meta.flow_id;
            }

        }
    };

    RegisterAction<id_freq_pair, bit<16>, bit<32>>(reg_id_freq) first_phase_clean =
    {
    void apply(inout id_freq_pair register_data, out bit<32> result) {
            register_data.id = 0;
            register_data.freq = 0;

        }
    };
    Register<bit<32>, bit<16>>(1) large_flow_reg;
    RegisterAction<bit<32>, bit<16>, bit<1>>(large_flow_reg) pend_large_flow_a =
    {
    void apply(inout bit<32> register_data, out bit<1> result) {
            if (meta.freq >= Hotlet_freq_thresh)
            {
                result = 1;
            }
            else result = 0;
            register_data = meta.freq;

        }
    };

    Register<bit<32>, bit<16>>(65536) tstamp_reg;
    RegisterAction<bit<32>, bit<16>, bit<1>>(tstamp_reg) pend_hotlet_a =
    {
    void apply(inout bit<32> register_data, out bit<1> result) {
            result = 0;
            if (meta.tstamp - register_data > Hotlet_ts_thresh && meta.freq >1)
            {
                result = 1;
            }
            register_data = meta.tstamp;
            
        }
    };
    RegisterAction<bit<32>, bit<16>, bit<1>>(tstamp_reg) pend_message_a =
    {
    void apply(inout bit<32> register_data, out bit<1> result) {
            result = 0;
            if (meta.tstamp - register_data >= message_thresh)
            {
                register_data = meta.tstamp;
                result = 1;
            }
    }
    };
    
    Register<bit<32>, bit<16>>(65536) hotlet_id_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(hotlet_id_reg) set_hotlet_sch_a =
    {
    void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data;
            if (register_data == 0 && meta.schedule_flag == 1)
            {
                register_data = meta.flow_id;
            }
            
            

        }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(hotlet_id_reg) clean_scheduler_id_a =
    {
    void apply(inout bit<32> register_data, out bit<32> result) {
            register_data = 0;
            
        }
    };
    Register<bit<32>, bit<16>>(65536) timestamp_sch_reg;
    RegisterAction<bit<32>, bit<16>, bit<1>>(timestamp_sch_reg) pend_hotlet_sch_a =
    {
    void apply(inout bit<32> register_data, out bit<1> result) {
           result = 0;
            if (meta.tstamp - register_data > Hotlet_ts_thresh)
            {
                result = 1;
            }
            register_data = meta.tstamp;
            
            

        }
    };
    RegisterAction<bit<32>, bit<16>, bit<1>>(timestamp_sch_reg) pend_message_sch_a =
    {
    void apply(inout bit<32> register_data, out bit<1> result) {
           result = 0;
            if (meta.tstamp - register_data >= message_thresh)
            {
                register_data = meta.tstamp;
                result = 1;
            }
            
            

        }
    };

    Register<bit<16>, bit<16>>(65536) port_reg;
    RegisterAction<bit<16>, bit<16>, bit<16>>(port_reg) set_port_reg_a =
    {
    void apply(inout bit<16> register_data, out bit<16> result) {
            if (meta.set_flag == 1)
            {
                register_data = meta.port_setting;
            }
            result = register_data;
            
            
            

        }
    };

    action cal_hash_dynamic_ecmp(){
        meta.tstamp = ig_intr_md.ingress_mac_tstamp[31:0];
        dynamic_ecmp = hash_dynamic_ecmp.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, meta.s_d_port,ig_intr_md.ingress_mac_tstamp});
    }

    @stage(0) table cal_hash_dynamic_ecmp_t{
        actions = {
            cal_hash_dynamic_ecmp;
        }
        default_action = cal_hash_dynamic_ecmp;
    }

    action cal_hash_static_ecmp(){
        static_ecmp = hash_static_ecmp.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, meta.s_d_port});
    }

    @stage(0) table cal_hash_static_ecmp_t{
        actions = {
            cal_hash_static_ecmp;
        }
        default_action = cal_hash_static_ecmp;
    }

    action cal_hash_index(){
       meta.index = hash_1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, meta.s_d_port});      
    }

    @stage(0) table cal_hash_index_t{
        actions = {
            cal_hash_index;
        }
        default_action = cal_hash_index;
    }

    action cal_hash_fp(){
        meta.flow_id = hash_fp.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol, meta.s_d_port});       
    }

    @stage(0) table cal_hash_fp_t{
        actions = {
            cal_hash_fp;
        }
        default_action = cal_hash_fp;
    }

    action ecmp_select_port(bit<16> dynamic_port, bit<16> static_port){
        meta.dynamic_ecmp_port = dynamic_port;
        meta.static_ecmp_port = static_port;
    }

    @stage(1) table ecmp_select_port_t{
        actions = {
            ecmp_select_port;
        }
        key = {
            hdr.ipv4.dst_addr: exact;
            dynamic_ecmp:   exact;
            static_ecmp:   exact;
        }
        size = 100;
        default_action = ecmp_select_port(0, 0);
    }

    action unicast_send(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }
    action drop(){
        ig_dprsr_md.drop_ctl = 1;
    }

    @stage(0) table arp_host{
        actions = {
            unicast_send;
            drop;
        }
        key = {
            hdr.arp.proto_dst_addr:   exact;
        }
        default_action = drop;
    }

    action port_set(){
        ig_tm_md.ucast_egress_port = (PortId_t)meta.final_output_port;
    }


    @stage(11) table port_set_t{
        actions = {
            port_set;
        }
        default_action = port_set;
    }

    action get_frequency(){
        meta.freq = first_phase.execute(meta.index);
    }

    @stage(1) table get_frequency_t{
        actions = {
            get_frequency;
        }
        default_action = get_frequency;
    }
    
    action clean_frequency(){
        first_phase_clean.execute(hdr.clean.index);
    }

    @stage(1) table clean_frequency_t{
        actions = {
            clean_frequency;
        }
        default_action = clean_frequency;
    }

    action pend_large_flow(){
        hot_flag = pend_large_flow_a.execute(0);
    }

    @stage(2) table pend_large_flow_t{
        actions = {
            pend_large_flow;
        }
        default_action = pend_large_flow;
    }

    action pend_hotlet(){
        flowlet_flag = pend_hotlet_a.execute(meta.index);
    }

    @stage(2) table pend_hotlet_t{
        actions = {
            pend_hotlet;
        }
        default_action = pend_hotlet;
    }

    action pend_message(){
        message_flag = pend_message_a.execute(meta.index);
    }

    @stage(2) table pend_message_t{
        actions = {
            pend_message;
        }
        default_action = pend_message;
    }
    bit<32> hotlet_id = 0xffffffff;
    action set_hotlet_sch(){
        hotlet_id = set_hotlet_sch_a.execute(meta.index);
    }

    @stage(4) table set_hotlet_sch_t{
        actions = {
            set_hotlet_sch;
        }
        default_action = set_hotlet_sch;
    }

    action clean_scheduler_id (){
        clean_scheduler_id_a.execute(hdr.clean.index);
    }

    @stage(4) table clean_scheduler_id_t{
        actions = {
            clean_scheduler_id;
        }
        default_action = clean_scheduler_id;
    }



     action pend_hotlet_sch(){
        flowlet_flag_sch = pend_hotlet_sch_a.execute(meta.index);
    }

    @stage(6) table pend_hotlet_sch_t{
        actions = {
            pend_hotlet_sch;
        }
        default_action = pend_hotlet_sch;
    }

    action pend_message_sch(){
        message_flag_sch = pend_message_sch_a.execute(meta.index);
    }

    @stage(6) table pend_message_sch_t{
        actions = {
            pend_message_sch;
        }
        default_action = pend_message_sch;
    }

    action hotlet_sch(){
        meta.final_output_port = set_port_reg_a.execute(meta.index);
    }

    @stage(8) table hotlet_sch_t{
        actions = {
            hotlet_sch;
        }
        default_action = hotlet_sch;
    }

    
    apply{

        if(hdr.arp.isValid()){
            arp_host.apply();
        }
        else if(hdr.ipv4.isValid()){
            cal_hash_dynamic_ecmp_t.apply(); //calulate ecmp
            cal_hash_static_ecmp_t.apply(); //calulate ecmp
            cal_hash_index_t.apply();
            cal_hash_fp_t.apply();
            ecmp_select_port_t.apply();//ecmp select port
            if (hdr.tcp.isValid())
            {   meta.mirror.ether_type = 0x3333;
                get_frequency_t.apply();
                pend_large_flow_t.apply();
                if (meta.freq != 0)
                pend_hotlet_t.apply();
                else
                pend_message_t.apply();
                /* 原id是0，flowlet，hot均为1，调度
                    原id等于现id，第二层timestamp超阈值，也调度
                    第二层timestamp超message，清空port，开始recirculate*/
                if (flowlet_flag == 1 && hot_flag == 1)
                {
                    meta.schedule_flag = 1;
                }
                set_hotlet_sch_t.apply();   
                if (hotlet_id == 0 && meta.schedule_flag == 1)
                {
                    zero_flag = 1;
                }
                if (hotlet_id == meta.flow_id || zero_flag == 1)
                {
                    pend_hotlet_sch_t.apply();
                    id_equal_flag = 1;
                }
                else
                pend_message_sch_t.apply();
                if (message_flag == 1)
                meta.mirror.clean_flag = meta.mirror.clean_flag + 128;
                if (zero_flag == 1 || flowlet_flag_sch == 1)
                {
                    meta.set_flag = 1;
                    port_select_flag = 1;
                    meta.port_setting = meta.dynamic_ecmp_port;
                }
                else if (id_equal_flag == 1)
                {
                    port_select_flag = 1;
                }
                if (message_flag_sch == 1)
                meta.mirror.clean_flag = meta.mirror.clean_flag + 64;
                if (port_select_flag == 1)
                {
                    hotlet_sch_t.apply();
                }
                else
                {
                    meta.final_output_port = meta.static_ecmp_port;
                }
                if (meta.mirror.clean_flag != 0)
                {
                    meta.session_id = 1;
                    meta.mirror.index = meta.index;
                    ig_dprsr_md.mirror_type = 1;
                }
                
            }
            else
            {
                meta.final_output_port = meta.static_ecmp_port;
            }
            port_set_t.apply();

        }
        else if (hdr.clean.isValid())
        {
            if (hdr.clean.detector_flag == 1)
            {
                clean_frequency_t.apply();
            }
            if (hdr.clean.scheduler_flag == 1)
            {
                clean_scheduler_id_t.apply();
            }
        }

    }

}

/**************************D E P A R S E R*******************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
        // Checksum() ipv4_checksum;
    
    
     Checksum() ipv4_checksum;
     Mirror() mirror;
    apply {
        if (ig_dprsr_md.mirror_type == 1)
        mirror.emit<mirror_h>(meta.session_id, meta.mirror);

        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.res,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });  
        }
        pkt.emit(hdr);
        
    }
}
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

    struct my_egress_headers_t {

    ethernet_h         ethernet;
    vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;

    }


    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

    struct my_egress_metadata_t {

    }

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    

    apply {
      }
}



    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
  
    apply {
          pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
