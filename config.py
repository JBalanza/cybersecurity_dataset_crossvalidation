#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import socket

if os.name == 'nt': #windows
    base_dir = r'C:\Users\JPortatil\Desktop\CarpetaCompartida\Datasets'
    dataset_iot23_dir = os.path.join(base_dir, 'iot_23\iot_23_subset')
else:
    base_dir = '/media/javier/Titan/TFM/procesados/'
    dataset_iot23_dir = os.path.join(base_dir, 'iot_23')
logfile = os.path.join(base_dir, 'processed.txt')
dataset_iot23_csv_file =  os.path.join(base_dir, 'iot_23_global.csv')
dataset_botnetiot_dir = os.path.join(base_dir, 'botnet_iot')
dataset_botnetiot_csv_file = os.path.join(base_dir, 'botnet_iot_global.csv')
database_file = os.path.join(base_dir, 'sqlite.db')
csv_slip_size = 3000000
conn_log_slip_size = 10000000

proto_table = {}
# Done with parse_prot_numbers
proto_table["HOPOPT"] = 0
proto_table["ICMP"] = 1
proto_table["IGMP"] = 2
proto_table["GGP"] = 3
proto_table["IPV4"] = 4
proto_table["ST"] = 5
proto_table["TCP"] = 6
proto_table["CBT"] = 7
proto_table["EGP"] = 8
proto_table["IGP"] = 9
proto_table["BBN-RCC-MON"] = 10
proto_table["NVP-II"] = 11
proto_table["PUP"] = 12
proto_table["ARGUS"] = 13
proto_table["EMCON"] = 14
proto_table["XNET"] = 15
proto_table["CHAOS"] = 16
proto_table["UDP"] = 17
proto_table["MUX"] = 18
proto_table["DCN-MEAS"] = 19
proto_table["HMP"] = 20
proto_table["PRM"] = 21
proto_table["XNS-IDP"] = 22
proto_table["TRUNK-1"] = 23
proto_table["TRUNK-2"] = 24
proto_table["LEAF-1"] = 25
proto_table["LEAF-2"] = 26
proto_table["RDP"] = 27
proto_table["IRTP"] = 28
proto_table["ISO-TP4"] = 29
proto_table["NETBLT"] = 30
proto_table["MFE-NSP"] = 31
proto_table["MERIT-INP"] = 32
proto_table["DCCP"] = 33
proto_table["3PC"] = 34
proto_table["IDPR"] = 35
proto_table["XTP"] = 36
proto_table["DDP"] = 37
proto_table["IDPR-CMTP"] = 38
proto_table["TP++"] = 39
proto_table["IL"] = 40
proto_table["IPV6"] = 41
proto_table["SDRP"] = 42
proto_table["IPV6-ROUTE"] = 43
proto_table["IPV6-FRAG"] = 44
proto_table["IDRP"] = 45
proto_table["RSVP"] = 46
proto_table["GRE"] = 47
proto_table["DSR"] = 48
proto_table["BNA"] = 49
proto_table["ESP"] = 50
proto_table["AH"] = 51
proto_table["I-NLSP"] = 52
proto_table["SWIPE (DEPRECATED)"] = 53
proto_table["NARP"] = 54
proto_table["MOBILE"] = 55
proto_table["TLSP"] = 56
proto_table["SKIP"] = 57
proto_table["IPV6-ICMP"] = 58
proto_table["IPV6-NONXT"] = 59
proto_table["IPV6-OPTS"] = 60
proto_table["CFTP"] = 62
proto_table["SAT-EXPAK"] = 64
proto_table["KRYPTOLAN"] = 65
proto_table["RVD"] = 66
proto_table["IPPC"] = 67
proto_table["SAT-MON"] = 69
proto_table["VISA"] = 70
proto_table["IPCV"] = 71
proto_table["CPNX"] = 72
proto_table["CPHB"] = 73
proto_table["WSN"] = 74
proto_table["PVP"] = 75
proto_table["BR-SAT-MON"] = 76
proto_table["SUN-ND"] = 77
proto_table["WB-MON"] = 78
proto_table["WB-EXPAK"] = 79
proto_table["ISO-IP"] = 80
proto_table["VMTP"] = 81
proto_table["SECURE-VMTP"] = 82
proto_table["VINES"] = 83
proto_table["TTP"] = 84
proto_table["IPTM"] = 84
proto_table["NSFNET-IGP"] = 85
proto_table["DGP"] = 86
proto_table["TCF"] = 87
proto_table["EIGRP"] = 88
proto_table["OSPFIGP"] = 89
proto_table["SPRITE-RPC"] = 90
proto_table["LARP"] = 91
proto_table["MTP"] = 92
proto_table["AX.25"] = 93
proto_table["IPIP"] = 94
proto_table["MICP"] = 95
proto_table["SCC-SP"] = 96
proto_table["ETHERIP"] = 97
proto_table["ENCAP"] = 98
proto_table["GMTP"] = 100
proto_table["IFMP"] = 101
proto_table["PNNI"] = 102
proto_table["PIM"] = 103
proto_table["ARIS"] = 104
proto_table["SCPS"] = 105
proto_table["QNX"] = 106
proto_table["A/N"] = 107
proto_table["IPCOMP"] = 108
proto_table["SNP"] = 109
proto_table["COMPAQ-PEER"] = 110
proto_table["IPX-IN-IP"] = 111
proto_table["VRRP"] = 112
proto_table["PGM"] = 113
proto_table["L2TP"] = 115
proto_table["DDX"] = 116
proto_table["IATP"] = 117
proto_table["STP"] = 118
proto_table["SRP"] = 119
proto_table["UTI"] = 120
proto_table["SMP"] = 121
proto_table["SM (DEPRECATED)"] = 122
proto_table["PTP"] = 123
proto_table["ISIS OVER IPV4"] = 124
proto_table["FIRE"] = 125
proto_table["CRTP"] = 126
proto_table["CRUDP"] = 127
proto_table["SSCOPMCE"] = 128
proto_table["IPLT"] = 129
proto_table["SPS"] = 130
proto_table["PIPE"] = 131
proto_table["SCTP"] = 132
proto_table["FC"] = 133
proto_table["RSVP-E2E-IGNORE"] = 134
proto_table["MOBILITY HEADER"] = 135
proto_table["UDPLITE"] = 136
proto_table["MPLS-IN-IP"] = 137
proto_table["MANET"] = 138
proto_table["HIP"] = 139
proto_table["SHIM6"] = 140
proto_table["WESP"] = 141
proto_table["ROHC"] = 142
proto_table["ETHERNET"] = 143
proto_table["RESERVED"] = 255
proto_table["ARP"] = 2054

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
