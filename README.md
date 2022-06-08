#
# Laporan Tugas Akhir
 Nama : Fauzan Adzima Tohari
 </br> NIM : 205150301111029
 </br>Mata Kuliah : Arsitektur Jaringan Terkini
 </br>Program Studi : Teknik Komputer
 #
# Kata Pengantar
Puji syukur kehadirat Tuhan Yang Maha Esa yang telah memberikan rahmat dan hidayah-Nya sehingga saya dapat dengan lancar menyusun laporan tugas akhir ini guna melengkapi tugas dari mata kuliah Arsitektur Jaringan Terkini. Laporan tugas akhir ini berisikan 4 bagian utama kegiatan pengulangan tugas yang pernah diberikan yakni dimulai dari tugas 1 hingga tugas 4. Saya sebagai penulis berharap semoga laporan yang telah saya buat sedemikian rupa dapat diterima dengan baik. Jika di dalam laporan ini terdapat kesalahan atau kekurangan, saya meminta permohonan maaf sebesar - besarnya. Demikian yang bisa saya sampaikan, saya ucapkan terima kasih.
#
### <b>TUGAS 1 MEMBUAT INSTANCE
</br> A. Pembuatan EC2 Instance di AWS Academy </b>
</br>Di dalam pembuatan dan melakukan pengerjaan tugas akhir ini, kita menggunakan salah satu platform cloud yakni Amazon Web Services (AWS) Academy. Sebelum masuk ke dalam pembahasan bagian utama, kita perlu memulainya dengan login akun AWS Academy terlebih dahulu. Setelah melakukan login, kita melanjutkan dengan membuat instance baru sesuai dengan ketentuan yang diberikan. Langkah - langkah dalam pembuatan instance sebagai berikut :

</br>Spesifikasi Instance :
</br> Name and tags: Tugas Akhir
</br> OS Images: Ubuntu Server 22.04 LTS 64 bit
</br> Instance type: t2.medium
</br> Key pair: vockey
</br> Edit Network settings: allow SSH, allow HTTP, allow HTTPS, allow TCP port 8080, allow TCP port 8081
</br> Configure storage: 30 GiB, gp3

</br> 1. Melakukan Name and tags: Tugas Akhir dan Melakukan pemilihan OS Images: Ubuntu Server 22.04 LTS 64 bit
</br> ![1  Nama Instances](https://user-images.githubusercontent.com/82666388/172537517-aef17425-ac86-4469-ab0c-33f8631e89ca.png)
</br></br> 2. Melakukan pemilihan Instance type: t2.medium dan  Key pair: vockey
</br>![2](https://user-images.githubusercontent.com/82666388/172538485-e66ce82c-71a5-4451-81b5-b23557be178a.png)
</br></br>3. Melakukan Edit Network settings: allow SSH, allow HTTP, allow HTTPS, allow TCP port 8080, allow TCP port 8081
</br>![3](https://user-images.githubusercontent.com/82666388/172538616-86c7d216-7f86-4da5-a887-318d29f27e5c.png)
</br></br>4. Melakukan Configure storage: 30 GiB, gp3
</br>![4](https://user-images.githubusercontent.com/82666388/172541772-01aca3c9-9b90-4f5f-9b51-405e2381cfcf.png)
</br></br>5. Berhasil membuat instance
</br>![5](https://user-images.githubusercontent.com/82666388/172541835-7d60efb3-6e20-4668-8280-bec47f7e7485.png)
</br></br><b>B. menghubungkannya dengan terminal ubuntu</b>
</br></br>6. Melakukan Update di dalam ubuntu
</br>![6](https://user-images.githubusercontent.com/82666388/172541878-22b87ea7-10a3-428c-b2c1-b694e1e7d0af.png)
</br></br>7. Unduh repositori Mininet
</br>![7](https://user-images.githubusercontent.com/82666388/172543773-a6e89313-b1f1-47e3-a56e-15b93e2581b4.png)
</br></br>8. Instal mininet
</br>![8](https://user-images.githubusercontent.com/82666388/172543801-ab1895aa-330d-4441-9d5c-297243b301e8.png)
</br></br>9. Unduh repository Ryu dan instal
</br>![9](https://user-images.githubusercontent.com/82666388/172543823-d82ee390-2db2-457a-aab3-4074820ee7c7.png)
</br></br>10. melakukan install pip
</br>![10](https://user-images.githubusercontent.com/82666388/172543848-8b35cf14-316a-417f-98e5-dd6825daf5d0.png)
</br></br>11. Unduh repository Flowmanager
</br> ![11](https://user-images.githubusercontent.com/82666388/172566688-7a2db033-b7fe-4845-8cfb-e35d151b7b83.png)
</br>
#
### </br><b>TUGAS 2 MEMBUAT CUSTOM TOPOLOGY</b> 
</br><b> A. Pembuatan Custom Topology Mininet Seperti pada Modul Tugas 2</b>
 </br></br>1. Pembuatan File berisi konfigurasi berekstensi .py
 </br>![1](https://user-images.githubusercontent.com/82666388/172578404-c0a138ac-e54e-4dab-9c05-b149fa539587.png)
 </br>2. Menjalankan mininet tanpa controller menggunakan custom topo yang sudah dibuat
 </br>![2](https://user-images.githubusercontent.com/82666388/172578476-415e153f-aa17-446a-87dd-3fb03e469979.png)
 </br>3. Buat flow agar h1 dapat terhubung dengan h2 
 </br>![3](https://user-images.githubusercontent.com/82666388/172578527-f5005caa-c06d-4ed0-8494-b05126d825ed.png)
 </br>4. Menguji koneksi agar h1 dengan h2
 </br>![4](https://user-images.githubusercontent.com/82666388/172578637-5f454090-0dd1-49a1-9def-ffb32b38eef3.png)

 </br></br><b>B. Tugas Membuat Program Untuk Custom Topology</b>
 </br></br>1. Pembuatan File Berisi Konfigurasi Berekstensi .py
 </br>![1](https://user-images.githubusercontent.com/82666388/172585138-1209fd1f-49a6-418b-982b-d22869c8bfab.png)
 </br>![2](https://user-images.githubusercontent.com/82666388/172585548-5050f945-6c03-4c46-8486-53af8ef70ebf.png)
 </br>2. Menjalankan mininet tanpa controller menggunakan custom topo yang sudah dibuat
 </br>![3](https://user-images.githubusercontent.com/82666388/172585625-ec3b15df-f4bd-43f6-8118-d2b19a1fe62d.png)
 </br>3. Buat flow agar h1 dapat terhubung dengan h2 
 </br>![4](https://user-images.githubusercontent.com/82666388/172585664-c8774591-de59-46c2-bbe5-d1ddbc66b462.png)
 </br></br>4. Melihat flow yang sudah terhubung
 </br>![5](https://user-images.githubusercontent.com/82666388/172586221-672b2991-e9b7-4701-95bb-dad807d5f661.png)
#
### </br><b>TUGAS 3 MEMBUAT APLIKASI RYU LOAD BALANCER</b>
</br><b> A. Pembuatan Aplikasi Ryu Load Balancer</b>
</br></br>1. Topology
</br>![topo](https://user-images.githubusercontent.com/82666388/172596460-3db3d94c-ee51-47b4-9d32-6348cf5db4fd.png)
</br></br>2. Program yang digunakan
 ```
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#Reference:
https://bitbucket.org/sdnhub/ryu-starter-kit/src/7a162d81f97d080c10beb
15d8653a8e0eff8a469/stateless_lb.py?at=master&fileviewer=file-view-
default
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,
MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types, arp, tcp, ipv4
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3
#from ryu.app.sdnhub_apps import learning_switch
class SimpleSwitch13(app_manager.RyuApp):
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
def __init__(self, *args, **kwargs):
super(SimpleSwitch13, self).__init__(*args, **kwargs)
self.mac_to_port = {}
self.serverlist=[] #Creating a list of servers
self.virtual_lb_ip = "10.0.0.100" #Virtual Load Balancer IP
self.virtual_lb_mac = "AB:BC:CD:EF:AB:BC" #Virtual Load Balancer MAC
Address
self.counter = 0 #Used to calculate mod in server selection belowself.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02",
"outport":"2"}) #Appending all given IP's, assumed MAC's and ports of
switch to which servers are connected to the list created
self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03",
"outport":"3"})
self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04",
"outport":"4"})
print("Done with initial setup related to server list creation.")
@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
datapath = ev.msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# install table-miss flow entry
#
# We specify NO BUFFER to max_len of the output action due to
# OVS bug. At this moment, if we specify a lesser number, e.g.,
# 128, OVS will send Packet-In with invalid buffer_id and
# truncated packet data. In that case, we cannot output packets
# correctly. The bug has been fixed in OVS v2.1.0.
match = parser.OFPMatch()
actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
ofproto.OFPCML_NO_BUFFER)]
self.add_flow(datapath, 0, match, actions)
def add_flow(self, datapath, priority, match, actions, buffer_id=None):
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
actions)]
if buffer_id:
mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
priority=priority, match=match,
instructions=inst)
else:
mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
match=match, instructions=inst)
datapath.send_msg(mod)
def function_for_arp_reply(self, dst_ip, dst_mac): #Function placed here,
source MAC and IP passed from below now become the destination for
the reply ppacket
print("(((Entered the ARP Reply function to build a packet and reply back
appropriately)))")
arp_target_ip = dst_ip
arp_target_mac = dst_mac
src_ip = self.virtual_lb_ip #Making the load balancers IP and MAC assource IP and MAC
src_mac = self.virtual_lb_mac
arp_opcode = 2 #ARP opcode is 2 for ARP reply
hardware_type = 1 #1 indicates Ethernet ie 10Mb
arp_protocol = 2048 #2048 means IPv4 packet
ether_protocol = 2054 #2054 indicates ARP protocol
len_of_mac = 6 #Indicates length of MAC in bytes
len_of_ip = 4 #Indicates length of IP in bytes
pkt = packet.Packet()
ether_frame = ethernet.ethernet(dst_mac, src_mac, ether_protocol)
#Dealing with only layer 2
arp_reply_pkt = arp.arp(hardware_type, arp_protocol, len_of_mac,
len_of_ip, arp_opcode, src_mac, src_ip, arp_target_mac, dst_ip) #Building
the ARP reply packet, dealing with layer 3
pkt.add_protocol(ether_frame)
pkt.add_protocol(arp_reply_pkt)
pkt.serialize()
print("{{{Exiting the ARP Reply Function as done with processing for ARP
reply packet}}}")
return pkt
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
# If you hit this you might want to increase
# the "miss_send_length" of your switch
if ev.msg.msg_len < ev.msg.total_len:
self.logger.debug("packet truncated: only %s of %s bytes",
ev.msg.msg_len, ev.msg.total_len)
msg = ev.msg
datapath = msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
in_port = msg.match['in_port']
dpid = datapath.id
#print("Debugging purpose dpid", dpid)
pkt = packet.Packet(msg.data)
eth = pkt.get_protocols(ethernet.ethernet)[0]
if eth.ethertype == ether_types.ETH_TYPE_LLDP:
# ignore lldp packet
return
if eth.ethertype == ether.ETH_TYPE_ARP: #If the ethernet frame has eth
type as 2054 indicating as ARP packet..
arp_header = pkt.get_protocols(arp.arp)[0]
if arp_header.dst_ip == self.virtual_lb_ip and arp_header.opcode ==
arp.ARP_REQUEST: #..and if the destination is the virtual IP of the load
balancer and Opcode = 1 indicating ARP Requestreply_packet=self.function_for_arp_reply(arp_header.src_ip,
arp_header.src_mac) #Call the function that would build a packet for ARP
reply passing source MAC and source IP
actions = [parser.OFPActionOutput(in_port)]
packet_out = parser.OFPPacketOut(datapath=datapath,
in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions,
buffer_id=0xffffffff)
datapath.send_msg(packet_out)
print("::::Sent the packet_out::::")
"""else: #Not needed as we ARP only for the load balancer MAC address.
This is needed when we ARP for other device's MAC
dst = eth.dst
src = eth.src
self.mac_to_port.setdefault(dpid, {})
self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
# learn a mac address to avoid FLOOD next time.
self.mac_to_port[dpid][src] = in_port
if dst in self.mac_to_port[dpid]:
out_port = self.mac_to_port[dpid][dst]
else:
out_port = ofproto.OFPP_FLOOD
actions = [parser.OFPActionOutput(out_port)]
# install a flow to avoid packet_in next time
if out_port != ofproto.OFPP_FLOOD:
match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
# verify if we have a valid buffer_id, if yes avoid to send both
# flow_mod & packet_out
if msg.buffer_id != ofproto.OFP_NO_BUFFER:
self.add_flow(datapath, 1, match, actions, msg.buffer_id)
return
else:
self.add_flow(datapath, 1, match, actions)
data = None
if msg.buffer_id == ofproto.OFP_NO_BUFFER:
data = msg.data
out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
in_port=in_port, actions=actions, data=data)
datapath.send_msg(out)"""
return
ip_header = pkt.get_protocols(ipv4.ipv4)[0]
#print("IP_Header", ip_header)
tcp_header = pkt.get_protocols(tcp.tcp)[0]
#print("TCP_Header", tcp_header)
count = self.counter % 3 #Round robin fashion setup
server_ip_selected = self.serverlist[count]['ip']
server_mac_selected = self.serverlist[count]['mac']
server_outport_selected = self.serverlist[count]['outport']server_outport_selected = int(server_outport_selected)
self.counter = self.counter + 1
print("The selected server is ===> ", server_ip_selected)
#Route to server
match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
eth_src=eth.src, eth_dst=eth.dst, ip_proto=ip_header.proto,
ipv4_src=ip_header.src, ipv4_dst=ip_header.dst,
tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port)
actions = [parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
parser.OFPActionSetField(eth_dst=server_mac_selected),
parser.OFPActionSetField(ipv4_dst=server_ip_selected),
parser.OFPActionOutput(server_outport_selected)]
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
actions)]
cookie = random.randint(0, 0xffffffffffffffff)
flow_mod = parser.OFPFlowMod(datapath=datapath, match=match,
idle_timeout=7, instructions=inst, buffer_id = msg.buffer_id,
cookie=cookie)
datapath.send_msg(flow_mod)
print("<========Packet from client: "+str(ip_header.src)+". Sent to
server: "+str(server_ip_selected)+", MAC: "+str(server_mac_selected)+"
and on switch port: "+str(server_outport_selected)+"========>")
#Reverse route from server
match = parser.OFPMatch(in_port=server_outport_selected,
eth_type=eth.ethertype, eth_src=server_mac_selected,
eth_dst=self.virtual_lb_mac, ip_proto=ip_header.proto,
ipv4_src=server_ip_selected, ipv4_dst=self.virtual_lb_ip,
tcp_src=tcp_header.dst_port, tcp_dst=tcp_header.src_port)
actions = [parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
parser.OFPActionSetField(ipv4_dst=ip_header.src),
parser.OFPActionSetField(eth_dst=eth.src),
parser.OFPActionOutput(in_port)]
inst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
actions)]
cookie = random.randint(0, 0xffffffffffffffff)
flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match,
idle_timeout=7, instructions=inst2, cookie=cookie)
datapath.send_msg(flow_mod2)
print("<++++++++Reply sent from server: "+str(server_ip_selected)+",
MAC: "+str(server_mac_selected)+". Via load balancer:
"+str(self.virtual_lb_ip)+".  
```
</br></br>2. Memodifikasi Source Code pada sisi server dengan ip, mac dan outport sebagai berikut dan menentukan virtual ip server: 10.0.0.100
```
self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02",
"outport":"2"}) 

self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03",
"outport":"3"}) 

self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04",
"outport":"4"}) 
```
</br>![3](https://user-images.githubusercontent.com/82666388/172598438-8c057f35-bde9-445d-8db7-62d244fe5f26.png)
</br></br>3. memasukan command ryu-manager pada terminal satu, dan melakukan perintah sudo mn --controller=remote --topo single,4 –mac pada terminal dua.
</br>![1](https://user-images.githubusercontent.com/82666388/172598896-1b42e5e9-d47b-442c-a4dd-75d15aad6f74.png)
</br>![2](https://user-images.githubusercontent.com/82666388/172598931-5ba5e3a9-2fb8-4330-87ef-e28cab5517a9.png)
</br></br>4. Pada bagian h2,h3,h4 akan menjadi web server yang akan memberikan paket ke client yaitu h1. Pada sisi h1 melakukan akses ke webserver dan di dapati dengan algoritma round robin yang memberikan paket ke h1 adalah server h2 dengan ip 10.0.0.2
</br>![4](https://user-images.githubusercontent.com/82666388/172599232-cad3aba9-ed3e-4ed3-b9a0-86d8de556352.png)
</br>![5](https://user-images.githubusercontent.com/82666388/172599375-53af410b-3fd0-4a8d-8f0e-e419c5a9f2bc.png)
</br></br>5. Melakukan akses kembali ke webserver kepada h1 berulang kali untuk 
memastikan algoritma Round-Robin berjalan dengan baik dan melakukan dpctl 
dump-flows -O openflow13 untuk melihat flow
</br>![6](https://user-images.githubusercontent.com/82666388/172599610-6b3768d1-0058-437d-9e4f-529b99bd771a.png)
</br>![7](https://user-images.githubusercontent.com/82666388/172599640-cd266372-713b-41d1-b9bd-5994ce6e220e.png)
# 
### </br><b>TUGAS 4 MEMBUAT APLIKASI RYU SHORTEST PATH ROUTING </b> 
</br><b> A. Pembuatan Aplikasi Ryu Shortest Path Routing</b>
 </br></br>1. Topology
 </br>![image](https://user-images.githubusercontent.com/82666388/172602613-835a9329-9e21-41b2-97a5-fa7e8b0e5527.png)
</br></br>2. Source Code
```
rom ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,
MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
# switches
switches = []
# mymacs[srcmac]->(switch, port)
mymacs = {}
# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))
# getting the node with lowest distance in Q
def minimum_distance(distance, Q):
min = float('Inf')
node = 0
for v in Q:
if distance[v] < min:
min = distance[v]
node = v
return node
def get_path (src, dst, first_port, final_port):
# executing Dijkstra's algorithm
print( "get_path function is called, src=", src," dst=", dst, " first_port=",
first_port, " final_port=", final_port)
# defining dictionaries for saving each node's distance and its previous
node in the path from first node to that node
distance = {}
previous = {}
# setting initial distance of every node to infinityfor dpid in switches:
distance[dpid] = float('Inf')
previous[dpid] = None
# setting distance of the source to 0
distance[src] = 0
# creating a set of all nodes
Q = set(switches)
# checking for all undiscovered nodes whether there is a path that goes
through them to their adjacent nodes which will make its adjacent nodes
closer to src
while len(Q) > 0:
# getting the closest node to src among undiscovered nodes
u = minimum_distance(distance, Q)
# removing the node from Q
Q.remove(u)
# calculate minimum distance for all adjacent nodes to u
for p in switches:
# if u and other switches are adjacent
if adjacency[u][p] != None:
# setting the weight to 1 so that we count the number of routers in the
path
w = 1
# if the path via u to p has lower cost then make the cost equal to this
new path's cost
if distance[u] + w < distance[p]:
distance[p] = distance[u] + w
previous[p] = u
# creating a list of switches between src and dst which are in the shortest
path obtained by Dijkstra's algorithm reversely
r = []
p = dst
r.append(p)
# set q to the last node before dst
q = previous[p]
while q is not None:
if q == src:
r.append(q)
break
p = q
r.append(p)
q = previous[p]
# reversing r as it was from dst to src
r.reverse()
# setting pathif src == dst:
path=[src]
else:
path=r
# Now adding in_port and out_port to the path
r = []
in_port = first_port
for s1, s2 in zip(path[:-1], path[1:]):
out_port = adjacency[s1][s2]
r.append((s1, in_port, out_port))
in_port = adjacency[s2][s1]
r.append((dst, in_port, final_port))
return r
class ProjectController(app_manager.RyuApp):
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
def __init__(self, *args, **kwargs):
super(ProjectController, self).__init__(*args, **kwargs)
self.topology_api_app = self
self.datapath_list = []
def install_path(self, p, ev, src_mac, dst_mac):
print("install_path function is called!")
#print( "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac)
msg = ev.msg
datapath = msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# adding path to flow table of each switch inside the shortest path
for sw, in_port, out_port in p:
#print( src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, "
out_port=", out_port)
# setting match part of the flow table
match = parser.OFPMatch(in_port=in_port, eth_src=src_mac,
eth_dst=dst_mac)
# setting actions part of the flow table
actions = [parser.OFPActionOutput(out_port)]
# getting the datapath
datapath = self.datapath_list[int(sw)-1]
# getting instructions based on the actions
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS ,
actions)]
mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
match=match, idle_timeout=0, hard_timeout=0,
priority=1, instructions=inst)
# finalizing the change to switch datapath
datapath.send_msg(mod)# defining event handler for setup and configuring of switches
@set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
def switch_features_handler(self , ev):
print("switch_features_handler function is called")
# getting the datapath, ofproto and parser objects of the event
datapath = ev.msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# setting match condition to nothing so that it will match to anything
match = parser.OFPMatch()
# setting action to send packets to OpenFlow Controller without buffering
actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
ofproto.OFPCML_NO_BUFFER)]
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS ,
actions)]
# setting the priority to 0 so that it will be that last entry to match any
packet inside any flow table
mod = datapath.ofproto_parser.OFPFlowMod(
datapath=datapath, match=match, cookie=0,
command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
priority=0, instructions=inst)
# finalizing the mod
datapath.send_msg(mod)
# defining an event handler for packets coming to switches event
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
# getting msg, datapath, ofproto and parser objects
msg = ev.msg
datapath = msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# getting the port switch received the packet with
in_port = msg.match['in_port']
# creating a packet encoder/decoder class with the raw data obtained by
msg
pkt = packet.Packet(msg.data)
# getting the protocl that matches the received packet
eth = pkt.get_protocol(ethernet.ethernet)
# avoid broadcasts from LLDP
if eth.ethertype == 35020 or eth.ethertype == 34525:
return
# getting source and destination of the link
dst = eth.dst
src = eth.src
dpid = datapath.id
print("packet in. src=", src, " dst=", dst," dpid=", dpid)# add the host to the mymacs of the first switch that gets the packet
if src not in mymacs.keys():
mymacs[src] = (dpid, in_port)
print("mymacs=", mymacs)
# finding shortest path if destination exists in mymacs
if dst in mymacs.keys():
print("destination is known.")
p = get_path(mymacs[src][0], mymacs[dst][0], mymacs[src][1],
mymacs[dst][1])
self.install_path(p, ev, src, dst)
print("installed path=", p)
out_port = p[0][2]
else:
print("destination is unknown.Flood has happened.")
out_port = ofproto.OFPP_FLOOD
# getting actions part of the flow table
actions = [parser.OFPActionOutput(out_port)]
data = None
if msg.buffer_id == ofproto.OFP_NO_BUFFER:
data = msg.data
out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
in_port=in_port,
actions=actions, data=data)
datapath.send_msg(out)
# defining an event handler for adding/deleting of switches, hosts, ports
and links event
events = [event.EventSwitchEnter,
event.EventSwitchLeave, event.EventPortAdd,
event.EventPortDelete, event.EventPortModify,
event.EventLinkAdd, event.EventLinkDelete]
@set_ev_cls(events)
def get_topology_data(self, ev):
global switches
print("get_topology_data is called.")
# getting the list of known switches
switch_list = get_switch(self.topology_api_app, None)
switches = [switch.dp.id for switch in switch_list]
print("current known switches=", switches)
# getting the list of datapaths from the list of switches
self.datapath_list = [switch.dp for switch in switch_list]
# sorting the datapath list based on their id so that indexing them in
install_function will be correct
self.datapath_list.sort(key=lambda dp: dp.id)
# getting the list of links between switcheslinks_list = get_link(self.topology_api_app, None)
mylinks = [(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for
link in links_list]
# setting adjacency of nodes
for s1, s2, port1, port2 in mylinks:
adjacency[s1][s2] = port1
adjacency[s2][s1] =
```
</br></br>3. Melakukan Git Clone
</br>![image](https://user-images.githubusercontent.com/82666388/172604145-ee050f51-29bf-4a42-812d-e1f7b55b9cc6.png)
</br></br>4.	Jalankan program Ryu-Dijkstra
</br>![image](https://user-images.githubusercontent.com/82666388/172604307-331d1901-79c0-47ef-93c4-4b206ebf203f.png)
</br></br>5. Pada Terminal Console 2 jalankan python3 topo-spf_lab.py
</br>![image](https://user-images.githubusercontent.com/82666388/172604532-0de1d49f-f6b3-4ebc-a93c-7571ae77d0ed.png)
</br></br>6.	Melakukan Cek Konektivitas 
</br>Pada Percobaan Pertama Pingall tidak semua paket terkirim
</br>![image](https://user-images.githubusercontent.com/82666388/172604654-c699b9ad-b1bf-4429-9822-3d3abfbf1f15.png)
</br>Pada Percobaan Kedua Pingall semua paket terkirim.
</br>![image](https://user-images.githubusercontent.com/82666388/172604813-89a65112-d5f3-4c52-85ec-631618b2931b.png)
</br></br>7.	Mengecek Flow dengan melakukan perintah dpctl dump-flows -O openflow13
Pada hal ini semua Flow sudah tertanam pada semua switchnya untuk semua tujuan sesuai dengan Topology.
</br>![image](https://user-images.githubusercontent.com/82666388/172605304-a0ef33cf-9e4d-4ee9-a9f9-19dbeecccd61.png)
</br>![image](https://user-images.githubusercontent.com/82666388/172605333-6776d4c5-63e5-4487-8616-dd8711bb5f6c.png)
</br>![image](https://user-images.githubusercontent.com/82666388/172605356-7fd8cdfa-2b5f-4773-92ee-97622bcd599e.png)
</br>![image](https://user-images.githubusercontent.com/82666388/172605391-6b5be669-d7b9-4156-9b64-d329c9b5d69a.png)

