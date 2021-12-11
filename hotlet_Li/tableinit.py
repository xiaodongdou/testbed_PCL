from ipaddress import ip_address

p4 = bfrt.hotlet_v1.pipe

path = "/mnt/onl/data/xiaodong/hotlet/table/"

'''ecmp_select'''
ecmp_select_conf = open(path+"ecmp_select.txt")

table = p4.Ingress.ecmp_select_port_t
table.clear()
for t in ecmp_select_conf:
    d = t.split()
    table.add_with_ecmp_select_port(dst_addr=ip_address(d[0]), ecmp=int(d[1]), port=int(d[2]))


arp_host_conf=open(path+"arp_host_conf.txt")

table=p4.Ingress.arp_host
table.clear()
for t in arp_host_conf:
    d=t.split()
    table.add_with_unicast_send(proto_dst_addr=ip_address(d[0]), port=int(d[1]))


table = p4.Ingress.id_identy_t
table.clear()
table.add_with_id_identy(resub)
