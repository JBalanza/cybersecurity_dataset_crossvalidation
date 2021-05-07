#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import socket

if os.name == 'nt': #windows
    base_dir = r'C:\Users\JPortatil\Desktop\CarpetaCompartida\Datasets'
else:
    base_dir = '/media/javier/Titan/TFM/procesados/'
logfile = os.path.join(base_dir, 'processed.txt')
dataset_iot23_dir = os.path.join(base_dir, 'iot_23\iot_23_subset')
dataset_iot23_csv_file =  os.path.join(base_dir, 'iot_23_global.csv')
dataset_botnetiot_dir = os.path.join(base_dir, 'botnet_iot')
dataset_botnetiot_csv_file = os.path.join(base_dir, 'botnet_iot_global.csv')
database_file = os.path.join(base_dir, 'sqlite.db')
csv_slip_size = 3000000
conn_log_slip_size = 10000000

proto_table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
proto_table = dict(zip(proto_table.values(), proto_table.keys()))
proto_table['ARP'] = 3
proto_table['IPV6-ICMP'] = 2
print(proto_table)

def add_logfile(entry):
    with open(logfile, 'a') as f:
        f.writelines([entry])

def check_logfile(entry):
    try:
        with open(logfile, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if entry in line:
                    return True
            else:
                return False
    except FileNotFoundError as fnfe:
        return False
