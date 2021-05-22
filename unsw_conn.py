import socket
from datetime import datetime
from dateutil import tz
import config

class unsw_conn_entry:
    def __init__(self, line):
        elemts = line.replace('\n','').split(",")

        self.id_orig_h = elemts[0]  # addr (e.g: 192.168.1.132)
        self.id_orig_p = elemts[1]  # port (e.g: 58687)
        self.id_resp_h = elemts[2]  # addr (e.g: 192.168.1.1)
        self.id_resp_p = elemts[3]  # port (e.g: 22)
        self.proto = int(config.proto_table[elemts[4].upper()])  # string-enum (e.g: 17)
        self.service = elemts[13]  # string-enum (e.g: dns)
        self.flow_duration = elemts[6]

        if elemts[48] == "0":  # string (e.g: benign)
            self.label = "benign"
        else:
            main_label = elemts[47]
            if main_label in "Backdoors":
                self.label = "backdoor"
            elif main_label in " Shellcode":
                self.label = "shellcode"
            else:
                self.label = "unknown"

    def __str__(self):
        return ",".join([self.ts, self.id_orig_h, self.id_orig_p, self.id_resp_h, self.id_resp_p, self.proto, self.label])

def parse_unsw_file(file):
    entries = []
    with open(file, 'r') as f:
        for line in f.readlines():
            if not line.startswith('#'):
                try:
                    unsw_entry = unsw_conn_entry(line)
                    if unsw_entry.label != "unknown":
                        entries.append(unsw_entry)
                except Exception as e:
                    #print("Error:", e)
                    continue
    return entries
