#! /usr/bin/env python

""" 
Script takes a filename input, opens that file, finds all URLs in the file, and prints them out.
To be used on the memory dump from the pintool.
"""
import sys
import re

filename = sys.argv[1]
text = open(filename, 'r').read()

# pay attention to the "non-greedy" regex using "*?" syntax
url_finder = r"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*?))"

result = re.finditer(url_finder, text)
for x in result: 
    print(x.group(0))

