#!/usr/bin/env python
# -*- coding: utf-8 -*-

import config
import zeek_conn
import os
from database import Database
from datetime import datetime


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
def insert_csv(dataset, csv):
    with open(csv, 'r') as file:
        lines = file.readlines()
        #headers = lines[0].split(",")
        #for e,i in enumerate(headers):
        #    print(e,i)
        del lines[0] #delete headers
        buffer = []
        for line in lines:
            elmts = line.split(",")
            src_addr = elmts[0]
            dst_addr = elmts[1]
            src_port = int(elmts[2])
            dst_port = int(elmts[3])
            proto = int(elmts[4])
            timestamp = datetime.fromisoformat(elmts[5])
            flow_duration = elmts[6] # Notused
            fwd_pkts_per_s = elmts[9]
            pkt_size_avg = elmts[58]
            pkt_len_min = elmts[24]
            pkt_len_mean = elmts[25]
            down_up_ratio = elmts[57]
            bwd_pkt_len_min = elmts[20]
            buffer.append([dataset, timestamp, src_addr, src_port, dst_addr, dst_port, proto, pkt_size_avg, pkt_len_min, pkt_len_mean, fwd_pkts_per_s, down_up_ratio, bwd_pkt_len_min])
        return ddbb.insert_features(buffer)

#TODO check timestamp before updating. Not in the paper but desirable IMO
def update_labels(database, file):
    entries = zeek_conn.get_lines(database, file)
    return ddbb.update_label_conn_log(entries)

def insert_all_data(dataset, dir):
    subsets = get_subsets(dir)
    for subset in subsets:
        entries_inserted = 0
        entries_labeled = 0
        pcaps, conn_log, csvs = get_files(subset)
        # print(zeek_conn.get_unique(zeek_entries, 'local_resp'))
        for csv in csvs:
            entries_inserted += insert_csv(dataset, csv)
        print("entries inserted from", subset, entries_inserted)
        for conn_file in conn_log:
            entries_labeled += update_labels(dataset, conn_file)
        print("entries labeled from", subset, entries_labeled)
        entries_cleaned = ddbb.delete_empty_entries()
        print("entries deleted from", subset, entries_cleaned)


## MAIN ##
ddbb = Database(config.database_file)
ddbb.create_tables()
ddbb.delete_empty_entries()
insert_all_data('iot23', config.dataset_iot23_dir)

#df = ddbb.dump_database()
#df.to_csv(config.csv_file, index=False)