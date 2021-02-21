#!/usr/bin/env python
# -*- coding: utf-8 -*-

import config
import zeek_conn
import os
from database import Database

#returns: given a directory, gives the pcap and conn.log.labeled files.
def get_files(dir):
    pcaps = []
    conn_file = []
    csvs = []
    for dp, dn, filenames in os.walk(dir):
        for f in filenames:
            if '.pcap' in f:
                pcaps.append(os.path.join(dp,f))
            elif 'conn.log.labeled' in f:
                conn_file.append(os.path.join(dp,f))
            elif '.csv' in f:
                csvs.append(os.path.join(dp,f))
            else:
                continue
    return pcaps, conn_file, csvs

def get_subsets(dir):
    subsets = []
    for dp, dn, filenames in os.walk(dir):
        for d in dn:
            subsets.append(os.path.join(dp,d))
    return subsets

#TODO bulk insert
def insert_csv(dataset, file):
    with open(csv, 'r') as file:
        lines = file.readlines()
        #headers = lines[0].split(",")
        #for e,i in enumerate(headers):
        #    print(e,i)
        del lines[0] #delete headers
        for line in lines:
            elmts = line.split(",")
            src_addr = elmts[0]
            dst_addr = elmts[1]
            src_port = elmts[2]
            dst_port = elmts[3]
            proto = elmts[4]
            timestamp = elmts[5]
            flow_duration = elmts[6] # Notused
            fwd_pkts_per_s = elmts[9]
            pkt_size_avg = elmts[58]
            pkt_len_min = elmts[24]
            pkt_len_mean = elmts[25]
            down_up_ratio = elmts[57]
            bwd_pkt_len_min = elmts[20]
            ddbb.insert_features(dataset, timestamp, src_addr, src_port, dst_addr, dst_port, proto, pkt_size_avg, pkt_len_min, pkt_len_mean, fwd_pkts_per_s, down_up_ratio, bwd_pkt_len_min)

#TODO check timestamp before updating. Not in the paper but desirable IMO
def update_labels(dataset,file):
    zeek_entries = zeek_conn.parse_zeek_conn(file)
    for entry in zeek_entries:
        ddbb.update_label_conn_log(dataset, entry.id_orig_h, entry.id_orig_p, entry.id_resp_h, entry.id_resp_p, entry.proto, entry.label)


## MAIN ##
ddbb = Database(config.database_file)
ddbb.create_tables()
subsets = get_subsets(config.dataset_iot23_dir)
pcaps, conn_log, csvs = get_files(subsets[0])
#print(zeek_conn.get_unique(zeek_entries, 'local_resp'))
for csv in csvs:
    #insert_csv('iot23',csv)
    pass
for conn_file in conn_log:
    update_labels('iot23',conn_file)
    pass
