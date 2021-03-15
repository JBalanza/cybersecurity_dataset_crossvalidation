#!/usr/bin/env python
# -*- coding: utf-8 -*-

import config
import zeek_conn
import os
from database import Database
from datetime import datetime

class csv_entry:
    def __init__(self, line):
        elmts = line.split(",")
        self.src_addr = elmts[0]
        self.dst_addr = elmts[1]
        self.src_port = elmts[2]
        self.dst_port = elmts[3]
        self.proto = int(elmts[4])
        self.timestamp = datetime.fromisoformat(elmts[5]).strftime("%Y-%m-%d %H:%M:%S")
        self.fwd_pkts_per_s = elmts[9]
        self.pkt_size_avg = elmts[58]
        self.pkt_len_min = elmts[24]
        self.pkt_len_mean = elmts[25]
        self.down_up_ratio = elmts[57]
        self.bwd_pkt_len_min = elmts[20]
        self.label = None
    def to_insert(self, dataset):
        return [dataset, self.timestamp, self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto,
                self.pkt_size_avg, self.pkt_len_min, self.pkt_len_mean, self.fwd_pkts_per_s, self.down_up_ratio,
                self.bwd_pkt_len_min, self.label]

#returns: given a directory, gives the pcap and conn.log.labeled files.
def get_files(dir):
    pcaps = []
    conn_file = []
    csvs = []
    for dp, dn, filenames in os.walk(dir):
        for f in filenames:
            if '.pcap' in f:
                pcaps.append(os.path.join(dp,f))
            elif 'conn' in f:
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

def update_labels(database, file):
    entries = zeek_conn.get_lines(database, file)
    updated = 0
    chunk_size = 10000
    chunks_total = int(len(entries)/chunk_size)
    for i,chunk in enumerate(list(chunks(entries, chunk_size))):
        print("Updated chunk", i,"/", chunks_total)
        updated += ddbb.update_label_conn_log(chunk)
    return updated

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

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

def insert_all_data_memory(dataset, dir):
    subsets = get_subsets(dir)
    entries_read = 0
    entries_labeled = 0
    for subset in subsets:
        try:
            pcaps, conn_log, csvs = get_files(subset)
            for csv in csvs:
                entries_array, read = create_entries_array(csv, {})
                entries_read += read
                print("entries read from", subset, entries_read)
                for conn_file in conn_log:
                    zeek_entries= zeek_conn.parse_zeek_conn(conn_file)
                    print("labels read:", len(zeek_entries))
                    updated = update_labels_csv_entries(entries_array, zeek_entries)
                    entries_labeled += updated
                    #Save some RAM
                    del zeek_entries
                print("entries labeled from", subset, entries_labeled)
                #insert into database
                for set_entries in entries_array.values():
                    buffer = []
                    for set_entries2 in set_entries.values():
                        #ddbb.insert_features_with_label(list(map(lambda ent: ent.to_insert(dataset),set_entries2)))
                        buffer.extend(list(map(lambda ent: ent.to_insert(dataset),set_entries2)))
                    ddbb.insert_features_with_label(buffer)
                entries_cleaned = ddbb.delete_empty_entries()
                #save some RAM
                del entries_array
                print("entries deleted from", subset, entries_cleaned)
        except IndexError as e:
            print(e)
            print(subset)


def create_entries_array(csv, buffer):
    read = 0
    with open(csv, 'r') as file:
        lines = file.readlines()
        del lines[0]  # delete headers
        for line in lines:
            elmts = line.split(",")
            src_addr = elmts[0]
            dst_addr = elmts[1]
            csv_elem = csv_entry(line)
            try:
                buffer[src_addr][dst_addr].append(csv_elem)
            except KeyError:
                try:
                    buffer[src_addr][dst_addr] = []
                    buffer[src_addr][dst_addr].append(csv_elem)
                except KeyError:
                    buffer[src_addr] = {}
                    buffer[src_addr][dst_addr] = []
                    buffer[src_addr][dst_addr].append(csv_elem)
            read += 1
    return buffer, read

def update_labels_csv_entries(csv_entries, zeek_entries):
    updated = 0
    for zeek in zeek_entries:
        try:
            for csv_entry1 in csv_entries[zeek.id_orig_h][zeek.id_resp_h]:
                if zeek.id_orig_p == csv_entry1.src_port and zeek.id_resp_p == csv_entry1.dst_port and zeek.proto == csv_entry1.proto and zeek.ts == csv_entry1.timestamp:
                    csv_entry1.label = zeek.label
                    updated += 1
        except KeyError:
            continue
    return updated

def chunk_file(file, chunk_size):
    file_number = 1
    filename = os.path.basename(file).split(".")[0]
    dir = os.path.dirname(file)
    chunked = False
    with open(file,'r') as f:
        lines = f.readlines()
        if len(lines) > chunk_size:
            chunked = True
            for chunk in list(chunks(lines, chunk_size)):
                with open(os.path.join(dir, filename + str(file_number)+".csv"), 'w') as chunk_file:
                    chunk_file.writelines(chunk)
                print("Chunked",file, "into", filename + str(file_number)+".csv")
                file_number += 1
    if chunked:
        print("Removing", file)
        os.remove(file)

#TODO delete whatever is not a .csv
def preprocess(dir):
    subsets = get_subsets(dir)
    for subset in subsets:
        pcaps, conn_log, csvs = get_files(subset)
        for csv in csvs:
            chunk_file(csv, config.csv_slip_size)
        for conn_file in conn_log:
            chunk_file(conn_file, config.conn_log_slip_size)

## MAIN ##
ddbb = Database(config.database_file)
ddbb.create_tables()
ddbb.delete_empty_entries()
preprocess(config.dataset_iot23_dir)
#insert_all_data_memory('iot23', config.dataset_iot23_dir)
#insert_all_data('iot23', config.dataset_iot23_dir)

#df = ddbb.dump_database()
#df.to_csv(config.csv_file, index=False)