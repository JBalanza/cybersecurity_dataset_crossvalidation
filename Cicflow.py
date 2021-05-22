#!/usr/bin/env python
# -*- coding: utf-8 -*-

from decimal import Decimal
from datetime import datetime

class cicflow_entry:
    def __init__(self, line):
        elmts = line.split(",")
        self.line = line.replace('"','').replace("\n","")
        self.src_addr = elmts[0]
        self.dst_addr = elmts[1]
        self.src_port = elmts[2]
        self.dst_port = elmts[3]
        self.proto = int(Decimal(elmts[4]))
        self.timestamp = datetime.fromisoformat(elmts[5]).strftime("%Y-%m-%d %H:%M:%S")
        self.flow_duration = elmts[6]
        self.label = None
    def to_insert(self, dataset):
        return [dataset, self.timestamp, self.src_addr, self.src_port, self.dst_addr, self.dst_port, self.proto,
                self.line, self.label]
