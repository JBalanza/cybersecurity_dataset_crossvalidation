import sqlite3
import pandas

class Database:
    def __init__(self, file):
        self.connection = sqlite3.connect(file)

    def create_tables(self):
        handler = self.connection.cursor()

        handler.execute('''CREATE TABLE IF NOT EXISTS ENTRIES(
                                [generated_id] INTEGER PRIMARY KEY,
                                [dataset] text,
                                [timestamp] date,
                                [src_addr] VARCHAR(16),
                                [src_port] int,
                                [dst_addr] VARCHAR(16),
                                [dst_port] int,
                                [proto] int,
                                [pkt_size_avg] real,
                                [pkt_len_min] real,
                                [pkt_len_mean] real,
                                [fwd_pkts_per_s] real,
                                [down_up_ratio] real,
                                [bwd_pkt_len_min] real,
                                [label] text)''')
        self.connection.commit()

    #big groups better first
    def create_tables_with_index(self):
        handler = self.connection.cursor()

        handler.execute('''CREATE TABLE IF NOT EXISTS ENTRIES(
                                [generated_id] INTEGER PRIMARY KEY,
                                [dataset] text,
                                [timestamp] date,
                                [src_addr] VARCHAR(16),
                                [src_port] int,
                                [dst_addr] VARCHAR(16),
                                [dst_port] int,
                                [proto] int,
                                [pkt_size_avg] real,
                                [pkt_len_min] real,
                                [pkt_len_mean] real,
                                [fwd_pkts_per_s] real,
                                [down_up_ratio] real,
                                [bwd_pkt_len_min] real,
                                [label] text)''')
        handler.execute('''CREATE UNIQUE INDEX idx ON ENTRIES(dataset,src_addr,dst_addr,dst_port)''')
        self.connection.commit()

    def update_label_conn_log(self, lines):
        handler = self.connection.cursor()
        handler.executemany('''UPDATE ENTRIES SET label=? WHERE dataset=? AND src_addr=? AND dst_addr=? AND dst_port=? AND src_port=? AND proto=? AND timestamp=? ''', lines)
        self.connection.commit()
        return handler.rowcount

    def insert_features(self, buffer):
        handler = self.connection.cursor()
        handler.executemany('''INSERT INTO ENTRIES(
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
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''', buffer)
        self.connection.commit()
        return handler.rowcount

    def insert_features_with_label(self, buffer):
        handler = self.connection.cursor()
        handler.executemany('''INSERT INTO ENTRIES(
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
            bwd_pkt_len_min,
            label
            ) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', buffer)
        self.connection.commit()
        return handler.rowcount

    def delete_empty_entries(self):
        handler = self.connection.cursor()
        handler.execute('''DELETE FROM ENTRIES WHERE label is null''')
        self.connection.commit()
        return handler.rowcount


    def dump_database(self, dataset):
        db_df = pandas.read_sql_query('''SELECT  
            pkt_size_avg,
            pkt_len_min,
            pkt_len_mean,
            fwd_pkts_per_s,
            down_up_ratio,
            bwd_pkt_len_min,
            label
        FROM ENTRIES
        WHERE 
            label is not NULL and dataset=?
        ''', self.connection, params=[dataset])
        return db_df

    #TODO delete those who have -99999 (introduced in dlows.py)

