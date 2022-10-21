#!/usr/bin/env python3

import os
import sys
import re
import json
import shutil
import traceback
from time import gmtime, strftime

class PWD_OBJECT_Item(object):
    def __init__(self, buffer):
        self.id = b''        
        self.username = b''        
        self.password = b''
        self.password_fix = b''        
        self.domain = b''   
        self.real_domain = b''        
        self.genpw = b''        

        self.parse( buffer )

    def parse( self, buffer ):
        bFlag = True
        index = 0
        buffer = buffer.strip()
        entry = buffer.split('" ')
        while bFlag:
            if entry[index].strip() == 'id':
                self.id = entry[index+1]
                index += 2
            elif entry[index].strip() == 'usernamedec':
                self.username = entry[index+1]
                index += 2
            elif entry[index].strip() == 'passworddec':
                self.password = entry[index+1]
                index += 2
            elif entry[index].strip() == 'passworddecfix':
                self.password_fix = entry[index+1]
                index += 2
            elif entry[index].strip() == 'realdomain2lvl':
                self.real_domain = entry[index+1]
                index += 2
            elif entry[index].strip() == 'domain2lvl':
                self.domain = entry[index+1]
                index += 2
            elif entry[index].strip() == 'genpwI':
                self.genpw = entry[index+1]
                index += 2
            else:
                index += 1
            if index >= len(entry): 
                bFlag = False
    def __str__(self):
        return "\t\tID: %s\n\t\t\tusername: %s\n\t\t\tpassword: %s\n\t\t\tpassword_fix: %s\n\t\t\tdomain: %s\n\t\t\treal domain: %s\n\t\t\tgenpw: %s\n" % ( self.id, self.username, self.password, self.password_fix, self.domain, self.real_domain, self.genpw)

class PWD_Object(object):
    def __init__(self, filename=None ):
        self.filename = filename
        self.entries = {}

    def parse(self, data=None):
        if data == None and not self.filename == None:
            with open(self.filename, 'r') as fd:
                data = fd.read()
        tmp = ''
        for char in data:
            if ord(char) < 0x20 or ord(char)>0x7f:
                tmp += ' '
            else:
                tmp += char
        tmp = tmp.strip()
        for a in tmp.split(" o\""):
            if a.strip() == '': continue
            l_entry = PWD_OBJECT_Item( a )
            if not l_entry.id in self.entries:
                self.entries[l_entry.id] = l_entry
        
    def __str__( self ):
        ret  = ''
        bFirst = True
        for e in self.entries:
            if not bFirst:
                ret += '\t\t' + "#"*40 + '\n\t\t'
            bFirst = False
            ret += str(self.entries[e])[2:]
        return ret 

def group_messages( data ):
    sp = data.split("</MSG>\n")
    ret = []
    for s in sp:
        if s[:5] == '<MSG>':
            ret.append( s[5:] )
    return ret

def parse_json( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        # Must fix the json structure. Missed the beginning bracket
        tmp = msg.split('"')
        aid = tmp[4]
        index = msg.rfind('}')
        msg = '{"%s%s' % ( aid, msg[:index+1])
        tmp = json.loads(msg)
        ret.append(json.dumps(tmp, indent=4))
    return ret
def parse_name( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if '","' in msg or msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_password( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if ('function' in msg.lower() and 'this.' in msg.lower()) or msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_username( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if '","' in msg or msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_aid( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_userconfig( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if "ok accts_version=" in msg or msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_pwd_object( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        memObject = PWD_Object( )
        memObject.parse( msg )
        if msg in ret:
            continue
        ret.append(str(memObject))
    return ret
def parse_glocalkey( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if 'y":"' == msg[:4]:
            msg = msg[4:]
        try:
            index = msg.find('","')
            msg = msg[:index]
        except:
            pass
        if msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_localkey( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_masterpassword( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if msg in ret:
            continue
        ret.append(msg)
    return ret
def parse_privkey( data, pid ):
    ret = []
    msgs = group_messages( data )
    for msg in msgs:
        msg = msg.strip()
        if msg in ret:
            continue
        ret.append(msg)
    return ret

def parse_filename( filename ):
    tmp = '.*lp_(.+?)_(.+)\.txt'
    result = re.search( tmp, filename )
    if result == None:
        print("Failed to parse filename")
        return None
    return (result.group(1), result.group(2))

def process_file( filename ):
    pid, l_type = parse_filename( filename )
    ret = None

    with open( filename, 'r') as fd:
        data = fd.read()
    if l_type == 'JSON':
        try:
            ret = parse_json( data , pid )
        except:
            ret = ["ERROR processing JSON file! See raw txt file"]
    elif l_type == 'NAME':
        ret = parse_name( data , pid )
    elif l_type == 'PASSWORD':
        ret = parse_password( data, pid )
    elif l_type == 'USERNAME':
        ret = parse_username( data, pid )
    elif l_type == 'AID':
        ret = parse_aid( data, pid )
    elif l_type == 'USER_CONFIG':
        ret = parse_userconfig( data, pid )
    elif l_type == 'PWD_MEM_OBJECT':
        ret = parse_pwd_object( data, pid )
    elif l_type == 'G_LOCAL_KEY':
        ret = parse_glocalkey( data, pid )
    elif l_type == 'LOCAL_KEY':
        ret = parse_localkey( data, pid )
    elif l_type == 'MASTER_PASSWORD':
        ret = parse_masterpassword( data, pid )
    elif l_type == 'PRIV_KEY':
        ret = parse_privkey( data, pid )
    else:
        print("ERROR: Couldn't determine type")
    return (pid, l_type, ret)

def print_lp( directory, data ):
    filename = "%s/lastpass_%s.txt" % (directory, strftime("%Y_%m_%d-%H_%M_%S", gmtime() ))
    ret = b''
    for pid in data:
        ret += b"#"*10 + b" %s " % str.encode(pid) + b"#"*10 + b"\n"
        for t in data[pid]:
            ret += b"\t" + b"*"*20 + b" %s " % str.encode(t) + b"*"*20 + b"\n"
            for a in data[pid][t]:
                try:
                    ret += b'\t\t' + b"#"*40 + b'\n'
                    ret += b'\t\t%s\n' % str.encode(a)
                except:
                    traceback.print_exc()
    ret += b'\n\nData also written to %s\n' % str.encode(filename)
    with open(filename, 'wb') as fd:
        fd.write( ret )
    shutil.copyfile( filename, '%s/out.txt' % directory )
def main():
    if not len(sys.argv) == 2:
        print("USAGE:  process_lp_files.py <directory containsing files>")
        sys.exit(1)
    directory = sys.argv[1]
    lastpass = {}
    for f in os.listdir(directory):
        if not ('lp_' == f[:3] and '.txt' ==f[-4:]):
            continue
        pid, l_type, data = process_file( directory + os.sep + f )
        os.remove( directory + os.sep + f )
        if data == None or len(data) == 0:
            continue
        if not pid in lastpass:
            lastpass[pid] = {}
        if not l_type in lastpass[pid]:
            lastpass[pid][l_type] = []
        lastpass[pid][l_type].extend( data)
    print_lp(directory, lastpass)

if __name__=='__main__':
    main()
