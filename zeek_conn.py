import socket
from datetime import datetime
from dateutil import tz

proto_table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
proto_table = dict(zip(proto_table.values(), proto_table.keys()))
tzone_iot23 = tz.gettz('Etc/GMT+4')

class zeek_conn_entry:
    def __init__(self, line):
        elemts = line.split()
        #Clean the entry
        for i in range(len(elemts)):
            if "-" in elemts[i]:
                elemts[i] = None

        self.ts = datetime.fromtimestamp(int(float(elemts[0])), tz=tzone_iot23).strftime("%Y-%m-%d %H:%M:%S") # time (e.g: 2018-01-30 1:11:59)
        self.uid = elemts[1] # string (e.g: CGm6jB4dXK71ZDWUDh)
        self.id_orig_h = elemts[2] # addr (e.g: 192.168.1.132)
        self.id_orig_p = elemts[3] # port (e.g: 58687)
        self.id_resp_h = elemts[4] # addr (e.g: 192.168.1.1)
        self.id_resp_p = elemts[5] # port (e.g: 22)
        self.proto = int(proto_table[elemts[6].upper()]) # string-enum (e.g: 17)
        self.service = elemts[7] # string-enum (e.g: dns)
        self.duration = elemts[8] # double (e.g: 0.114184)
        self.orig_bytes = elemts[9] # int (e.g: 48)
        self.resp_bytes = elemts[10] # int (e.g: 48)
        self.conn_state = elemts[11] # string (e.g: SF, S0, OTH)
        self.local_orig = elemts[12] # bool
        self.local_resp = elemts[13] # bool
        self.missed_bytes = elemts[14] # int (e.g: 0)
        self.history = elemts[15] # string (e.g: ShAFf, Dd)
        self.orig_pkts = elemts[16] # int (e.g: 1)
        self.orig_ip_bytes = elemts[17] # int (e.g: 40)
        self.resp_pkts = elemts[18] # int (e.g: 1)
        self.resp_ip_bytes = elemts[19] # int (e.g: 40)
        self.tunnel_parents = elemts[20]
        self.label = elemts[21] # string (e.g: benign)
        self.detailed_label = elemts[22] # string (e.g: )


def parse_zeek_conn(file):
    entries = []
    with open(file, 'r') as f:
        for line in f.readlines():
            if not line.startswith('#'):
                entries.append(zeek_conn_entry(line))
    return entries

#changes
def get_lines(database, file):
    entries = []
    with open(file, 'r') as f:
        for line in f.readlines():
            if not line.startswith('#'):
                elemts = line.split()
                ts = datetime.fromtimestamp(int(float(elemts[0])), tz=tzone_iot23).strftime("%Y-%m-%d %H:%M:%S")
                id_orig_h = elemts[2]  # addr (e.g: 192.168.1.132)
                id_orig_p = int(elemts[3])  # port (e.g: 58687)
                id_resp_h = elemts[4]  # addr (e.g: 192.168.1.1)
                id_resp_p = int(elemts[5])  # port (e.g: 22)
                proto = proto_table[elemts[6].upper()]  # string-enum (e.g: udp)
                label = elemts[21]  # string (e.g: benign)
                entries.append([label, database, id_orig_h, id_resp_h, id_resp_p, id_orig_p, proto, ts])
    return entries

def get_unique(entries, field):
    unique = []
    for ent in entries:
        var = getattr(ent, field)
        if var not in unique:
            unique.append(var)
    return unique



