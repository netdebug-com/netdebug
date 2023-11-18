#!/usr/bin/env python3

import csv
import json
import sys

"""
How to use: 

   sqlite3 --csv  test_input_connections.sqlite3 'SELECT * from connections' | python conn-measurement-conversion-helper.py > out.csv

then open sqlite: 
   sqlite3 new.sqlite3

and type the following: 

    CREATE TABLE IF NOT EXISTS connections (id INTEGER PRIMARY KEY, saved_at DATETIME, measurements TEXT);
    .mode csv
    .import out.csv

then 
mv new.sqlite3 test_input_connections.sqlite3
rm out.csv

"""

reader = csv.reader(sys.stdin)
writer = csv.writer(sys.stdout)
for row in reader: 
    conn_raw = row[2]
    conn = json.loads(conn_raw)
    key = {}
    for field in ["local_ip", "local_l4_port", "remote_ip", "remote_l4_port", "ip_proto"]:
        key[field] = conn[field]
        del conn[field]
    conn["key"] = key
    writer.writerow([row[0], row[1], json.dumps(conn)])


