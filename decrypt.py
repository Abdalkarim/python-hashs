#!/usr/bin/python
#coding:utf-8
#Decrpt any hash with any type...
#Author : Mahmoud Abd Alkarim(@Maakthon)

from hashlib import *
from sys import *
        
if len(argv) < 4 or len(argv) > 4 :
    print("\n[!] Usage : python script.py Type(ex:md5) Hash(ex:9193ce3b31332b0) FileName\n")
    exit(1)
try:
    hash_type  = str(argv[1])
    hash_value = str(argv[2])
    file_name  = str(argv[3])
except:
    pass
    
def hash_types(file_name,hash_type,hash_value):
    if hash_type == 'md5' or hash_type == 'MD5' or len(hash_value) == 32:
        try:            
            with open(file_name,'r') as _file_:
                for line in _file_:
                    line = line.strip()
                    if md5(line.encode()).hexdigest() == hash_value:
                        print("Found it >>> {0}".format(line)) 
        except IOError:
            print("File name ERROR...")
################################################################################### 
    elif hash_type == 'sha1' or hash_type == 'SHA1' or len(hash_value) == 40:
                            
        try:            
            with open(file_name,'r') as _file_:
                for line in _file_:
                    line = line.strip()
                    if sha1(line.encode()).hexdigest() == hash_value:
                        print("Found it >>> {0}".format(line))
        except IOError:
            print("File name ERROR...")  
###################################################################################         
    elif hash_type == 'sha224' or hash_type == 'SHA224' or len(hash_value) == 56:
                            
        try:            
            with open(file_name,'r') as _file_:
                for line in _file_:
                    line = line.strip()
                    if sha224(line.encode()).hexdigest() == hash_value:
                        print("Found it >>> {0}".format(line))
        except IOError:
            print("File name ERROR...")
###################################################################################
    elif hash_type == 'sha256' or hash_type == 'SHA256' or len(hash_value) == 64:
                            
        try:            
            with open(file_name,'r') as _file_:
                for line in _file_:
                    line = line.strip()
                    if sha256(line.encode()).hexdigest() == hash_value:
                        print("Found it >>> {0}".format(line))
        except IOError:
            print("File name ERROR...")
###################################################################################
    elif hash_type == 'sha384' or hash_type == 'SHA384' or len(hash_value) == 96:
                            
        try:            
            with open(file_name,'r') as _file_:
                for line in _file_:
                    line = line.strip()
                    if sha384(line.encode()).hexdigest() == hash_value:
                        print("Found it >>> {0}".format(line))  
        except IOError:
            print("File name ERROR...")
###################################################################################
    elif hash_type == 'sha512' or hash_type == 'SHA512' or len(hash_value) == 128:
                            
        try:            
            with open(file_name,'r') as _file_:
                for line in _file_:
                    line = line.strip()
                    if sha512(line.encode()).hexdigest() == hash_value:
                        print("Found it >>> {0}".format(line))
        except IOError:
            print("File name ERROR...")            
###################################################################################            
    else:
        print("[*]Please (HASH TYPE) must be one of them : \nmd5\nsha1\nsha224\nsha256\nsha384\nsha512 ")

if __name__ == '__main__':
    try:    
        hash_types(file_name,hash_type,hash_value)        
    except:
        pass
