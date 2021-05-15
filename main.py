#!/usr/bin/env python
# -*- coding: utf-8 -*-

import config
import zeek_conn
import argus_conn
import os
from database import Database
from datetime import datetime
from Cicflow import cicflow_entry
import unsw_conn

#returns: given a directory, gives the pcap and conn.log.labeled files.
# TODO modify to get files in the botnet iot file structure
def get_files(dir):
    pcaps = []
    conn_file = []
    argus = []
    labels = []
    csvs = []
    for dp, dn, filenames in os.walk(dir):
        for f in filenames:
            if '.pcap' in f:
                pcaps.append(os.path.join(dp,f))
            elif 'conn' in f:
                conn_file.append(os.path.join(dp,f))
            elif 'argus' in f:
                argus.append(os.path.join(dp, f))
            elif 'labels' in f:
                labels.append(os.path.join(dp, f))
            elif '.csv' in f:
                csvs.append(os.path.join(dp,f))
            else:
                continue
    return pcaps, conn_file, csvs, argus, labels

def get_subsets(dir):
    subsets = []
    for dp, dn, filenames in os.walk(dir):
        for d in dn:
            subsets.append(os.path.join(dp,d))
        break
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
        pcaps, conn_log, csvs, _ = get_files(subset)
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
            pcaps, conn_log, csvs, argus, labels = get_files(subset)
            if dataset == 'iot23':
                for csv in csvs:
                    if not config.check_logfile(csv):
                        entries_array, read = create_entries_array(csv, {})
                        entries_read += read
                        print(datetime.now())
                        print("entries read from", csv, entries_read)
                        for conn_file in conn_log:
                            zeek_entries = zeek_conn.parse_zeek_conn(conn_file)
                            print("labels read from:", conn_file, len(zeek_entries))
                            updated = update_labels_csv_entries(entries_array, zeek_entries)
                            entries_labeled += updated
                            #Save some RAM
                            del zeek_entries
                        print("entries labeled from", conn_file, entries_labeled)
                        #insert into database
                        for set_entries in entries_array.values():
                            buffer = []
                            for set_entries2 in set_entries.values():
                                #ddbb.insert_features_with_label(list(map(lambda ent: ent.to_insert(dataset),set_entries2)))
                                buffer.extend(list(map(lambda ent: ent.to_insert(dataset),set_entries2)))
                            ddbb.insert_features_with_label(buffer)
                        config.add_logfile(csv)
                        #save some RAM
                        del entries_array
                        # not labeled are ok instead of deletion.
                        #entries_unknown = ddbb.add_label_to_empty('unknown')
                        # Delete entries with no label
                        entries_unknown = ddbb.delete_empty_entries()
                        # dump database to csv and clean to speed up
                        df = ddbb.dump_all_database()
                        df.to_csv(config.dataset_iot23_csv_file, mode="a", index=False, header=False)
                        ddbb.delete_all_entries()
                        print("entries unknown from", subset, entries_unknown)
                    else:
                        print("csv already processed:", csv)
            elif dataset == 'botnet_iot':
                # processed file to do not repeat
                for csv in csvs:
                    if not config.check_logfile(csv):
                        entries_array, read = create_entries_array(csv, {})
                        entries_read += read
                        print(datetime.now())
                        print("entries read from", csv, entries_read)
                        for argus_file in argus:
                            argus_entries = argus_conn.parse_argus_conn(argus_file)
                            print("labels read from", argus_file, ":", len(argus_entries))
                            updated = update_labels_csv_entries(entries_array, argus_entries)
                            entries_labeled += updated
                            # Save some RAM
                            del argus_entries
                        print("entries labeled from", argus_file, entries_labeled)
                        # insert into database
                        for set_entries in entries_array.values():
                            buffer = []
                            for set_entries2 in set_entries.values():
                                # ddbb.insert_features_with_label(list(map(lambda ent: ent.to_insert(dataset),set_entries2)))
                                buffer.extend(list(map(lambda ent: ent.to_insert(dataset), set_entries2)))
                            ddbb.insert_features_with_label(buffer)
                        # save some RAM
                        del entries_array
                        # Add file to log
                        config.add_logfile(csv)
                        # Add benign to empty label entries
                        entries_unknown = ddbb.add_label_to_empty('unknown')
                        # dump database to csv and clean to speed up
                        df = ddbb.dump_all_database()
                        df.to_csv(config.dataset_botnetiot_csv_file, mode="a", index=False)
                        ddbb.delete_all_entries()

                        print("entries unknown from", subset, entries_unknown)
                    else:
                        print("csv already processed:",csv)
            elif dataset == 'UNSW_NB15':
                unsw_labels = unsw_conn.parse_unsw_file(labels[0]) #There is only one and is short
                print("labels read from", labels[0], ":", len(unsw_labels))
                for csv in csvs:
                    if not config.check_logfile(csv):
                        print(datetime.now())
                        entries_array, read = create_entries_array(csv, {})
                        print("entries read from", csv, read)
                        updated = update_labels_csv_entries(entries_array, unsw_labels)
                        print("entries labeled from", csv, updated)
                        # insert into database
                        for set_entries in entries_array.values():
                            buffer = []
                            for set_entries2 in set_entries.values():
                                # ddbb.insert_features_with_label(list(map(lambda ent: ent.to_insert(dataset),set_entries2)))
                                buffer.extend(list(map(lambda ent: ent.to_insert(dataset), set_entries2)))
                            ddbb.insert_features_with_label(buffer)
                        # save some RAM
                        del entries_array
                        # Add file to log
                        config.add_logfile(csv)
                        # Add benign to empty label entries
                        #entries_unknown = ddbb.add_label_to_empty('unknown')
                        # Delete entries with no label
                        ddbb.delete_empty_entries()
			# dump database to csv and clean to speed up
                        df = ddbb.dump_all_database()
                        if df[df.columns[0]].count() > 1:
                            df.to_csv(config.dataset_nbsw_csv_file, mode="a", index=False)
                        ddbb.delete_all_entries()
                        #print("entries unknown from", csv, entries_unknown)
                else:
                    print("csv already processed:", csv)
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
            try:
                csv_elem = cicflow_entry(line)
                buffer[src_addr][dst_addr].append(csv_elem)
            except KeyError:
                try:
                    buffer[src_addr][dst_addr] = []
                    buffer[src_addr][dst_addr].append(csv_elem)
                except KeyError:
                    buffer[src_addr] = {}
                    buffer[src_addr][dst_addr] = []
                    buffer[src_addr][dst_addr].append(csv_elem)
            except ValueError:
                    continue
            read += 1
    return buffer, read

def update_labels_csv_entries(csv_entries, label_entries):
    updated = 0
    for entry in label_entries:
        try:
            for csv_entry1 in csv_entries[entry.id_orig_h][entry.id_resp_h]:
                if entry.id_orig_p == csv_entry1.src_port and entry.id_resp_p == csv_entry1.dst_port and entry.proto == csv_entry1.proto: # and entry.ts == csv_entry1.timestamp:
                    csv_entry1.label = entry.label
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
        pcaps, conn_log, csvs, _ = get_files(subset)
        for csv in csvs:
            chunk_file(csv, config.csv_slip_size)
        for conn_file in conn_log:
            chunk_file(conn_file, config.conn_log_slip_size)
	#for argus_file in conn_log:
	#    chunk_file(argus_file, config.conn_log_slip_size)

## MAIN ##
print("Start at:", datetime.now())
ddbb = Database(config.database_file)
ddbb.create_tables()
ddbb.delete_empty_entries()
#preprocess(config.dataset_iot23_dir)
#insert_all_data_memory('iot23', config.dataset_iot23_dir)
#insert_all_data('iot23', config.dataset_iot23_dir)

#insert_all_data_memory('botnet_iot', config.dataset_botnetiot_dir)
insert_all_data_memory('UNSW_NB15', config.dataset_nbsw_dir)

#df = ddbb.dump_database('iot23')
#df.to_csv(config.dataset_iot23_csv_file, index=False)

print("Ends at:", datetime.now())

