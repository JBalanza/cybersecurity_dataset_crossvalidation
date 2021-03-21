import socket
from datetime import datetime
from dateutil import tz
import config

tzone_botnetiot = tz.gettz('Etc/GMT+4')

class argus_conn_entry:
    def __init__(self, line):
        elemts = line.replace('"',"").split(";")
        #Clean the entry
        for i in range(len(elemts)):
            if len(elemts[i]) == 0:
                elemts[i] = None
        self.ts = datetime.fromtimestamp(int(float(elemts[0])), tz=tzone_botnetiot).strftime("%Y-%m-%d %H:%M:%S") # time (e.g: 2018-01-30 1:11:59)
        self.proto = int(config.proto_table[elemts[2].upper()]) # string-enum (e.g: 17)
        self.id_orig_h = elemts[3] # addr (e.g: 192.168.1.132)
        self.id_orig_p = elemts[4] # port (e.g: 58687 or empty ej:arp)
        self.id_resp_h = elemts[6] # addr (e.g: 192.168.1.1)
        self.id_resp_p = elemts[7] # port (e.g: 22)
        if "0" in elemts[34]:
            self.label = "benign" # string (e.g: benign)
        else:
            self.label = "malicious"

    def __str__(self):
        return ",".join([self.ts,self.id_orig_h,self.id_orig_p,self.id_resp_h, self.id_resp_p, self.proto, self.label])

def parse_argus_conn(file):
    entries = []
    with open(file, 'r') as f:
        for line in f.readlines():
            if not line.startswith('"'):
                entries.append(argus_conn_entry(line))
    return entries

def get_unique(entries, field):
    unique = []
    for ent in entries:
        var = getattr(ent, field)
        if var not in unique:
            unique.append(var)
    return unique



