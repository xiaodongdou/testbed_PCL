/* -*- P4_16 -*- */
//need to handle ARP
#include <core.p4>
#include <tna.p4>

#define PRIME 2147483647
#define flowlet_thresh 4000000
#define entry_num 65536
#define  ECN_MARK_THRESHOLD 10
#define  MIRROR_THRESHOLD  100000
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
enum bit<16> ether_type_t {
    TPID       = 0x8100,
    IPV4       = 0x0800,
    ARP        = 0x0806,
    QDE        = 0x3333
}

enum bit<8>  ip_proto_t {
    ICMP  = 1,
    IGMP  = 2,
    TCP   = 6,
    UDP   = 17
}
struct dt_res {
    bit<32>  dt;
    bit<32>  res;
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
    bit<6>       dscp;
    bit<2>       ecn;
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

header mirror_h {
    bit<48>  dst_addr;
    bit<48>  src_dst;
    bit<16>  ether_type;
    bit<16>  egress_port;
    bit<16>  qdepth;
}

header qde_h {
    bit<16>  egress_port;
    bit<16>  qdepth;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h         ethernet;
    qde_h              qde;
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
    bit<32> ll;
    bit<32> ts_now;
    bit<32> ts_last;
    bit<16> selected_port;
    bit<8> flag;
    bit<32> deltatime;
	bit<16> index;
    bit<32> cc;
    bit<1>  qde_flag;
    bit<16> port_qdepth;
    bit<16> port_1;
    bit<16> port_2;
    int<16> qdepth_port_1;
    int<16> qdepth_port_2;
    int<16> qdepth_dif;
    int<32> inttime;
    int<32> ft; 
}

    /***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.ll=0;
        meta.deltatime=0;
        meta.ts_now=0;
        meta.ts_last=0;
        meta.selected_port=0;
        meta.flag=0;
        meta.index=0;
        meta.cc=0;
        meta.inttime=0;
        meta.ft=0;
        meta.qde_flag = 0;
        meta.port_qdepth = 0;
        meta.port_1 = 0;
        meta.port_2 = 0;
        meta.qdepth_port_2 = 0;
        meta.qdepth_port_1 = 0;
        meta.qdepth_dif = 0;
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        /* 
         * The explicit cast allows us to use ternary matching on
         * serializable enum
         */        
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.ARP             :  parse_arp;
            (bit<16>)ether_type_t.QDE             :  parse_qde;
            default :  accept;
        }
    }

    state parse_qde {
        pkt.extract(hdr.qde);
        transition accept;
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
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
       meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.icmp);
        transition accept;
    }
    
    state parse_igmp {
      meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.igmp);
        transition accept;
    }
    
    state parse_tcp {
    meta.ll=pkt.lookahead<bit<32>>();
        pkt.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
      meta.ll=pkt.lookahead<bit<32>>();
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

bit<1> port_select = 0;



//bit<32> errorcode=0;
    CRCPolynomial<bit<32>>(0x04C11DB7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32a;
    CRCPolynomial<bit<32>>(0x741B8CD7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32b;
    CRCPolynomial<bit<32>>(0xDB710641,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32c;
    CRCPolynomial<bit<32>>(0x82608EDB,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32fp;

    Hash<bit<16>>(HashAlgorithm_t.CUSTOM,crc32a) hash_1;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32b) hash_2;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32c) hash_3;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32a) hash_i1;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32b) hash_i2;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM,crc32c) hash_i3;
    Hash<bit<1>>(HashAlgorithm_t.CUSTOM,crc32c) hash_ecmp;
    Hash<bit<14>>(HashAlgorithm_t.CUSTOM,crc32fp) hash_fp;
    Hash<bit<14>>(HashAlgorithm_t.CUSTOM,crc32fp) hash_fpi;


   /********select minium qdepth to send **********/
Register<bit<16>,bit<16>>(0x100) qdepth_reg_1;
RegisterAction<bit<16>,bit<16>,bit<16>>(qdepth_reg_1) qdepth_insert_1 = {
    void apply(inout bit<16> register_data, out bit<16> result){
        
            register_data =meta.port_qdepth;
        
        
    }
};
RegisterAction<bit<16>,bit<16>,bit<16>>(qdepth_reg_1) qdepth_query_1 = {
    void apply(inout bit<16> register_data, out bit<16> result){
        result = register_data;
        
    }
};
action qde_insert_1(){
    qdepth_insert_1.execute(hdr.qde.egress_port);
}

table qde_insert_1_t{
    actions = {
        qde_insert_1;
    }
    default_action = qde_insert_1;
}

Register<bit<16>,bit<16>>(0x100) qdepth_reg_2;
RegisterAction<bit<16>,bit<16>,bit<16>>(qdepth_reg_2) qdepth_insert_2 = {
    void apply(inout bit<16> register_data, out bit<16> result){
        
            register_data = meta.port_qdepth;
    }
};
RegisterAction<bit<16>,bit<16>,bit<16>>(qdepth_reg_2) qdepth_query_2 = {
    void apply(inout bit<16> register_data, out bit<16> result){
        result = register_data;
    }
};
action qde_insert_2(){
    qdepth_insert_2.execute(hdr.qde.egress_port);
}

table qde_insert_2_t{
    actions = {
        qde_insert_2;
    }
    default_action = qde_insert_2;
}

action route_equ(bit<16> port_1, bit<16> port_2){
    meta.port_1 = port_1;
    meta.port_2 = port_2;
}

table route_equ_t{
    key = {
        hdr.ipv4.dst_addr: exact;
    }
    actions = {
        route_equ;
    }
    size = 100;
    default_action = route_equ(0,0);
}
bit<16> qdepth_1;
bit<16> qdepth_2;
action qdepth_query_port1(){
    qdepth_1 = qdepth_query_1.execute(meta.port_1);
    meta.qdepth_port_1[14:0] = qdepth_1[14:0];
    // meta.qdepth_port_2 = qdepth_query_2.execute(meta.port_2);
}

table qdepth_query_port1_t{
    actions = {
        qdepth_query_port1;
    }
    default_action = qdepth_query_port1;
}
action qdepth_query_port2(){
    qdepth_2= qdepth_query_2.execute(meta.port_2);
    meta.qdepth_port_2[14:0] = qdepth_2[14:0];
}

table qdepth_query_port2_t{
    actions = {
        qdepth_query_port2;
    }
    default_action = qdepth_query_port2;
}
Register<int<16>, bit<16>>(0x1) cmp_qde_reg;
RegisterAction<int<16>, bit<16>, bit<1>>(cmp_qde_reg) cmp_qde=
{
    void apply(inout int<16> register_data, out bit<1> result) {
        // if(meta.qdepth_port_1 >= meta.qdepth_port_2){
        //     result = 1;
        // }  

        if(meta.qdepth_dif> 0){
            result = 1;
        }

    }
};

action cmp_qdepth(){
    
    port_select = cmp_qde.execute(0);
}

table cmp_qdepth_t{
    actions = {
        cmp_qdepth;
    }
    default_action = cmp_qdepth;
}

action get_qdepth_dif(){
    meta.qdepth_dif = meta.qdepth_port_1 - meta.qdepth_port_2;
}

table qdepth_dif_t{
    actions = {
        get_qdepth_dif;
    }
    default_action = get_qdepth_dif;
}

/********typical flowlet ***/


Register<bit<32>, bit<16>>(1) flowlet_reg;
RegisterAction<bit<32>, bit<16>, bit<32>>(flowlet_reg) flowlet_count=
    {
        void apply(inout bit<32> register_data) {
        	
            register_data=register_data+1;
        }
    };


Register<int<32>, bit<16>>(1) delta_reg;
RegisterAction<int<32>, bit<16>, bit<1>>(delta_reg) delta_pend=
    {
void apply(inout int<32> register_data, out bit<1> result) {
        
            if (meta.inttime>0)
            result=1;
            else
            result=0;

            register_data=meta.inttime;
        }
    };



Register<bit<32>, bit<16>>(entry_num) ts_reg;
RegisterAction<bit<32>, bit<16>, bit<32>>(ts_reg) output_ts_last=
    {
void apply(inout bit<32> register_data, out bit<32> result) {
        
            result=register_data;
            register_data=meta.ts_now;
        }
    };

Register<bit<16>, bit<16>>(entry_num) port_reg;
RegisterAction<bit<16>, bit<16>, bit<16>>(port_reg) output_port=
    {
void apply(inout bit<16> register_data, out bit<16> result) {
        
            if (meta.flag>0)
            register_data=meta.selected_port;

            result=register_data;
        }
    };
action pend_thresh()//index
    {
        meta.flag[1:1]=delta_pend.execute(0);
    }
  table pend_thresh_t
    {
        actions={pend_thresh;}
        default_action=pend_thresh;
    }
   // hash_1.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,meta.ll,hdr.ipv4.protocol}
action get_ts_last()//index
    {
        meta.ts_last=output_ts_last.execute(meta.index);//hash_1.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,meta.ll,hdr.ipv4.protocol}));
    }
  table get_ts_last_t
    {
        actions={get_ts_last;}
        default_action=get_ts_last;
    }
bit<16> outport=0;
action get_port()//index
    {
        outport=output_port.execute(meta.index);//hash_1.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,meta.ll,hdr.ipv4.protocol}));
    }
  table get_port_t
    {
        actions={get_port;}
        default_action=get_port;
    }




action get_ts_now()//index
    {
        meta.ts_now=ig_intr_md.ingress_mac_tstamp[31:0];
    }
  table get_ts_now_t
    {
        actions={get_ts_now;}
        default_action=get_ts_now;
    }


action get_delta()//index
    {
        meta.deltatime=meta.ts_now-meta.ts_last;
    }
  table get_delta_t
    {
        actions={get_delta;}
        default_action=get_delta;
    }

action get_int()//index
    {
        meta.inttime[30:0]=meta.deltatime[30:0];
    }
  table get_int_t
    {
        actions={get_int;}
        default_action=get_int;
    }
action get_thresh(int<32> ft)//index
    {
        meta.ft=ft;
    }
  table get_thresh_t
    {
        actions={get_thresh;}
        default_action=get_thresh(200000);
    }


action del_int()//index
    {
        meta.inttime=meta.inttime-meta.ft;
    }
  table del_int_t
    {
        actions={del_int;}
        default_action=del_int;
    }
bit<1> ecmp=0;
action cal_ecmp()//index
    {
        ecmp=hash_ecmp.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,meta.ll,hdr.ipv4.protocol,ig_intr_md.ingress_mac_tstamp});
    }
  table cal_ecmp_t
    {
        actions={cal_ecmp;}
        default_action=cal_ecmp;
    }

bit<1> ecmp_able=0;
action if_ecmp(bit<1> sign)//index
    {
        ecmp_able=sign;
    }
  table if_ecmp_t
    {
        key={hdr.ipv4.dst_addr:exact;}
        actions={if_ecmp;}
        default_action=if_ecmp(0);
    }



action ecmp_select(bit<16> port)//index
    {
        meta.selected_port=port;
        hdr.ipv4.ttl=hdr.ipv4.ttl-1;
    }
  table ecmp_select_t
    {   
        key={hdr.ipv4.dst_addr:exact;ecmp:exact;}
        actions={ecmp_select;}
        default_action=ecmp_select(0);
        size=100;
    }
    /* arp packets processing */
    action unicast_send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress=1;
    }
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
    table arp_host {
        key = { hdr.arp.proto_dst_addr : exact; }
        actions = { unicast_send; drop; }
        default_action = drop();
    }


    Register<bit<32>, bit<16>>(0x1) data_counter_reg_i;
    RegisterAction<bit<32>, bit<16>, bit<16>>(data_counter_reg_i) data_count_i=
    {
        void apply(inout bit<32> register_data) {
        	
            register_data= register_data +(bit<32>)meta.port_qdepth;
        }
    };



apply{

    if (hdr.arp.isValid())
    {
        arp_host.apply();
    }
    else if (hdr.ipv4.isValid())
    {   
        cal_ecmp_t.apply();
        meta.index=hash_1.get({hdr.ipv4.src_addr,hdr.ipv4.dst_addr,meta.ll,hdr.ipv4.protocol});
        if_ecmp_t.apply();
        ecmp_select_t.apply();

        //select port 
        route_equ_t.apply();
        qdepth_query_port1_t.apply();
        qdepth_query_port2_t.apply();
        qdepth_dif_t.apply();
        cmp_qdepth_t.apply();
        if(port_select == 1){
            meta.selected_port = meta.port_2;
        }
        else meta.selected_port = meta.port_1;

        if (ecmp_able==1)
        {   
            // get_thresh_t.apply();
            get_ts_now_t.apply();
            get_ts_last_t.apply();
            get_delta_t.apply();
            if (meta.ts_last==0)
                meta.flag[0:0]=1;
            get_int_t.apply();
            del_int_t.apply();
            pend_thresh_t.apply();
            get_port_t.apply();
            ig_tm_md.ucast_egress_port=(PortId_t)outport;
            if (meta.flag==2)
                flowlet_count.execute(0);
        }
        else
        {
            ig_tm_md.ucast_egress_port=(PortId_t)meta.selected_port;
        }
        
    }
    else if(hdr.qde.isValid()){
        meta.qde_flag = 1;
        meta.port_qdepth = hdr.qde.qdepth;
        qde_insert_1_t.apply();
        qde_insert_2_t.apply();
        ig_dprsr_md.drop_ctl = 1;
        data_count_i.execute(0);
    }
}

}
control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
        // Checksum() ipv4_checksum;
    
    
     Checksum() ipv4_checksum;
    
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
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
    arp_h              arp;
    vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;

    }


    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

    struct my_egress_metadata_t {
        bit<16>     qdepth;
        bit<16>     ecn_thres;
        bit<32>     ts_now_e;
        bit<32>     ts_last_e;
        bit<32>     ts_dif_e;
        bit<1>      mirror_flag;
        int<32>     mirror_theres;
        int<32>     ts_int_e;
        int<32>     int_thre_dif;
        mirror_h    mirror;
        MirrorId_t  session_id;
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
        // pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }
    state meta_init{
        meta.qdepth = 0;
        meta.ecn_thres = 0;
        meta.mirror_flag = 0;
        meta.ts_now_e = 0;
        meta.ts_last_e = 0;
        meta.ts_dif_e = 0;
        meta.ts_int_e = 0;
        meta.mirror_theres = 0;
        transition parse_ethernet;
    }

    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.ARP             :  parse_arp;
            default :  accept;
        }       
    }

    state parse_arp {
        pkt.extract(hdr.arp);
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
        transition  accept;  
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

    Register<bit<32>,bit<16>>(0x1) ts_mirror_reg;
    RegisterAction<bit<32>,bit<16>,bit<32>>(ts_mirror_reg) ts_mirror_a = 
    {
        void apply(inout bit<32> register_data, out bit<32> result){
            result = register_data;
            register_data = meta.ts_now_e;
        }
    };

    action get_ts_last_e(){
        meta.ts_last_e = ts_mirror_a.execute(0);
    }

    table get_ts_last_e_t{
        actions = {
            get_ts_last_e;
        }
        default_action = get_ts_last_e;
    }
    action get_ts_dif_e(){
        meta.ts_dif_e = meta.ts_now_e - meta.ts_last_e;
    }

    table get_ts_dif_e_t{
        actions = {
            get_ts_dif_e;
        }
        default_action = get_ts_dif_e;
    }

    action get_ts_now_e(){
        meta.ts_now_e = eg_prsr_md.global_tstamp[31:0];
        // meta.ts_now_e = 0;
    }

    table get_ts_now_e_t{
        actions = {
            get_ts_now_e;
        }
        default_action = get_ts_now_e;
    }

    action get_thres_e(int<32> mirror_th){
        meta.mirror_theres = mirror_th;
    }

    table get_thres_e_t{
        actions = {
            get_thres_e;
        }
        default_action = get_thres_e(400000);
    }

    action get_ts_int(){
        meta.ts_int_e[30:0] = meta.ts_dif_e[30:0];
    }

    table get_ts_int_t{
        actions = {
            get_ts_int;
        }
        default_action = get_ts_int;
    }

    action get_ts_dif_thres(){
        meta.int_thre_dif = meta.ts_int_e - meta.mirror_theres;
    }

    table get_ts_dif_thres_t{
        actions={
            get_ts_dif_thres;
        }
        default_action = get_ts_dif_thres;
    }

    Register<int<32>,bit<16>>(0x1) cmp_ts_mirror;
    RegisterAction<int<32>,bit<16>,bit<1>>(cmp_ts_mirror) cmp_mirror={
        void apply(inout int<32> register_data, out bit<1> result){
            if(meta.int_thre_dif > 0){
                result = 1;
            }
            else result = 0;
        }
    };

    action set_mirror_flag(){
        meta.mirror_flag = cmp_mirror.execute(0);
    }

    table set_mirror_flag_t{
        actions = {
            set_mirror_flag;
        }
        default_action = set_mirror_flag;
    }

    action set_mirror_header(){
        meta.mirror.egress_port = (bit<16>)eg_intr_md.egress_port;
        meta.mirror.qdepth = eg_intr_md.enq_qdepth[15:0];
    }

    table set_mirror_header_t{
        actions = {
            set_mirror_header;
        }
        default_action = set_mirror_header;
    }


     //ecn set 
    action mark_ecn(){
        hdr.ipv4.ecn = 3;
    }

    table mark_ecn_t{
        actions = {
            mark_ecn;
        }
        default_action = mark_ecn;
    }

    Register<bit<16>,bit<16>>(0x1) ecn_reg;
    RegisterAction<bit<16>,bit<16>,bit<1>>(ecn_reg) cmp_ecn_thres = 
    {
        void apply(inout bit<16> register_data, out bit<1> result){
            register_data = meta.qdepth;
            if(register_data > ECN_MARK_THRESHOLD){
                result = 1;
            }
            else result = 0;
        }
    };

bit<1> ecn_flag = 0;
    action set_ecn_flag(){
        ecn_flag = cmp_ecn_thres.execute(0);
    }

    table set_ecn_flag_t{
        actions = {
            set_ecn_flag;
        }
        default_action = set_ecn_flag;
    }

    action ecn_qdepth(){
        meta.qdepth = eg_intr_md.enq_qdepth[15:0];
        
    }

    table ecn_qdepth_t{
        actions = {
            ecn_qdepth;
        }
        default_action = ecn_qdepth();
    }

    Register<bit<32>, bit<16>>(1) data_counter_reg_e;
    RegisterAction<bit<32>, bit<16>, bit<32>>(data_counter_reg_e) data_count_e=
    {
        void apply(inout bit<32> register_data) {
        	
            register_data=register_data+(bit<32>)meta.mirror.qdepth;
        }
    };

    

    apply {
        if(hdr.ipv4.ecn == 1 || hdr.ipv4.ecn ==2){
            ecn_qdepth_t.apply();
            set_ecn_flag_t.apply();
            if(ecn_flag == 1){
                mark_ecn_t.apply();
            }
        }

        get_ts_now_e_t.apply();
        get_ts_last_e_t.apply();
        get_ts_dif_e_t.apply();
        get_thres_e_t.apply();
        get_ts_int_t.apply();
        get_ts_dif_thres_t.apply();
        set_mirror_flag_t.apply();

        if(meta.mirror_flag == 1){
            meta.mirror.ether_type = 0x3333;
            meta.session_id = 1;
            set_mirror_header_t.apply();
            eg_dprsr_md.mirror_type = 1;
            data_count_e.execute(0);
        }
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
    Checksum() ipv4_checksum;
    Mirror() mirror;
    
    apply {

        if(eg_dprsr_md.mirror_type == 1){
            mirror.emit<mirror_h>(meta.session_id, meta.mirror);
        }

        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
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
