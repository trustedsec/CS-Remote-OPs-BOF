#!/usr/bin/env python3

import sys
import json
import base64

def parse_token( token ):
    token = token.strip()
    parts = token.split('.')
    if len(parts) < 2: return 'Invalid'
    headerb64 = parts[0]
    packageb64 = parts[1]

    ret = ''
    t = len(headerb64)%4
    headerb64 += '='*t
    header = base64.b64decode( headerb64 )
    packageb64 = packageb64.replace('-','+').replace('_','/')
    t = len(packageb64)%4
    packageb64 += '='*t
    package = base64.b64decode( packageb64 )
    return json.dumps(json.loads(header.decode('utf-8')),indent=4) +"\n\n"+json.dumps(json.loads(package.decode('utf-8')),indent=4)

if len(sys.argv) != 2:
    print("USAGE: parse_jwt.py <filename>")
    sys.exit(1)

filename = sys.argv[1]

with open(filename, 'r') as fd:
    tokens = fd.readlines()

for token in tokens:
    print( parse_token( token ))
