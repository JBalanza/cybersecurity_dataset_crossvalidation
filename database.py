import sqlite3
import os
import socket

class Database:
    def __init__(self, file):
        self.connection = sqlite3.connect(file)
        self.proto_table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
        print(self.proto_table)
    def create_tables(self):
        handler = self.connection.cursor()

        handler.execute('''CREATE TABLE IF NOT EXISTS ENTRIES(
                                [generated_id] INTEGER PRIMARY KEY,
                                [dataset] text,
                                [timestamp] date,
                                [src_addr] text,
                                [src_port] int,
                                [dst_addr] text,
                                [dst_port] int,
                                [proto] text,
                                [pkt_size_avg] real,
                                [pkt_len_min] real,
                                [pkt_len_mean] real,
                                [fwd_pkts_per_s] real,
                                [down_up_ratio] real,
                                [bwd_pkt_len_min] real,
                                [label] text)''')
        self.connection.commit()

    def update_label_conn_log(self, dataset, src_addr, src_port, dst_addr, dst_port, proto, label):
        handler = self.connection.cursor()
        input = [label, dataset, src_addr, src_port, dst_addr, dst_port, proto]
        handler.execute('''UPDATE ENTRIES SET label=? WHERE dataset=? AND src_addr=? AND src_port=? AND dst_addr=? AND dst_port=? AND proto=?''', input)
        self.connection.commit()
        return

    def insert_features(self, dataset, timestamp, src_addr, src_port, dst_addr, dst_port, proto, pkt_size_avg, pkt_len_min, pkt_len_mean, fwd_pkts_per_s, down_up_ratio, bwd_pkt_len_min):
        handler = self.connection.cursor()
        input = [ dataset, timestamp, src_addr, src_port, dst_addr, dst_port, self.proto_table[int(proto)], pkt_size_avg, pkt_len_min, pkt_len_mean, fwd_pkts_per_s, down_up_ratio, bwd_pkt_len_min]
        handler.execute('''INSERT INTO ENTRIES(
            dataset,
            timestamp,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            proto,
            pkt_size_avg,
            pkt_len_min,
            pkt_len_mean,
            fwd_pkts_per_s,
            down_up_ratio,
            bwd_pkt_len_min
            ) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''', input)
        self.connection.commit()