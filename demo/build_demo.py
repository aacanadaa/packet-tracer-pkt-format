"""Demo lab: two sites, OSPF between the routers, generated without Packet Tracer."""
from pkt_core import Lab

lab = Lab()
lab.prune_seed_devices()

R1 = ["hostname R1",
      "interface GigabitEthernet0/0", " ip address 10.0.1.1 255.255.255.0", " no shutdown",
      "interface GigabitEthernet0/1", " ip address 10.0.12.1 255.255.255.0", " no shutdown",
      "router ospf 1", " network 10.0.1.0 0.0.0.255 area 0", " network 10.0.12.0 0.0.0.255 area 0",
      "end"]
R2 = ["hostname R2",
      "interface GigabitEthernet0/0", " ip address 10.0.2.1 255.255.255.0", " no shutdown",
      "interface GigabitEthernet0/1", " ip address 10.0.12.2 255.255.255.0", " no shutdown",
      "router ospf 1", " network 10.0.2.0 0.0.0.255 area 0", " network 10.0.12.0 0.0.0.255 area 0",
      "end"]

r1 = lab.add_device("2911", "R1", 300, 250, ios_config=R1)
r2 = lab.add_device("2911", "R2", 760, 250, ios_config=R2)
sw1 = lab.add_device("2960-24TT", "SW1", 300, 410)
sw2 = lab.add_device("2960-24TT", "SW2", 760, 410)
pc1 = lab.add_device("PC-PT", "PC1", 160, 540, pc_ip=("10.0.1.10", "255.255.255.0", "10.0.1.1"))
pc2 = lab.add_device("PC-PT", "PC2", 900, 540, pc_ip=("10.0.2.10", "255.255.255.0", "10.0.2.1"))

lab.link(r1, "GigabitEthernet0/0", sw1, "GigabitEthernet0/1")
lab.link(sw1, "FastEthernet0/1", pc1, "FastEthernet0")
lab.link(r1, "GigabitEthernet0/1", r2, "GigabitEthernet0/1")
lab.link(r2, "GigabitEthernet0/0", sw2, "GigabitEthernet0/1")
lab.link(sw2, "FastEthernet0/1", pc2, "FastEthernet0")

lab.save("ospf_lab.pkt")
print("saved ospf_lab.pkt")
