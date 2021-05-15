import os

file = r'./protocol-numbers-1.csv'
with open(file, 'r') as f:
    for line in f.readlines():
        try:
            elements = line.split(',')
            number = int(elements[0])
            proto_name = elements[1].upper()
            print("proto_table[\""+proto_name+"\"] =", number)

        except Exception as e:
            continue