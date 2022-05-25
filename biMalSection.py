#!/usr/bin/python

import pefile
import sys
import argparse
import os
import pprint
import networkx
import re
from networkx.drawing.nx_agraph import write_dot
import collections
from networkx.algorithms import bipartite

args = argparse.ArgumentParser("Generate a bipartite graph between samples and section names for the data in the specified directory")
args.add_argument("target_path",help="directory with malware samples")
args.add_argument("output_file",help="file to write DOT file to")
args.add_argument("malware_projection",help="file to write DOT file to")
args.add_argument("PEsectionname_projection",help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()
sectionSet = set()
sampleDict = {}

# search the target directory for valid Windows PE executable files
for root,dirs,files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root,path))
        except pefile.PEFormatError:
            continue
        fullpath = os.path.join(root,path)
        # extract printable strings from the target sample
        strings = os.popen("strings '{0}'".format(fullpath)).read()
        valid_senames = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}', strings)
        network.add_node(path,label=path[:32],color='black',penwidth=5,bipartite=0)
        #pe = pefile.PE(path)
        for section in pe.sections:
            sname = str(section.Name)
            if sname not in sectionSet:
                network.add_node(sname,label=sname,color='blue',penwidth=10,bipartite=1)
            if sname in strings:
                network.add_edge(sname,path,penwidth=2)
            sectionSet.add(sname)
            if path not in sampleDict:
                sampleDict[path]=(set())
                sampleDict[path].add(sname)
            else:
                sampleDict[path].add(sname)
                     		 
# write the dot file to disk
write_dot(network, args.output_file)
malware = set(n for n,d in network.nodes(data=True) if d['bipartite']==0)
PEsectionname = set(network)-malware

# use NetworkX's bipartite network projection function to produce the malware
# and hostname projections
malware_network = bipartite.projected_graph(network, malware)
PEsectionname_network = bipartite.projected_graph(network, PEsectionname)

# write the projected networks to disk as specified by the user
write_dot(malware_network,args.malware_projection)
write_dot(PEsectionname_network,args.PEsectionname_projection)
