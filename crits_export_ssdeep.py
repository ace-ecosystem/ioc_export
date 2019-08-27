#!/usr/bin/env python
import os
import argparse
from configparser import ConfigParser
import pprint

from pymongo import MongoClient
from bson.objectid import ObjectId
from bson.json_util import dumps

parser = argparse.ArgumentParser(description="Exports ssdeep CRITS indicators into json, gets loaded into ACE.")
parser.add_argument('-c', '--config', default='etc/detect_export.ini', dest='config_path',
    help="Configuration file to load.")
args = parser.parse_args()

config = ConfigParser()
config.read(args.config_path)

client = MongoClient('localhost', 27017)
db = client.crits

allsources = db.indicators.distinct('source.name')
sources = []
not_sources = config['sources']['not']
not_mimetypes = "application/vnd.ms-excel,application/vnd.ms-office,application/msword,application/CDFV2-corrupt"
for src in allsources:
    if src and src not in not_sources:
       sources.append(src)
print(sources)

collection = db.indicators.find({"status":"Analyzed",'type':'Hash - SSDEEP',"source.name":{"$in":sources}})

data = { 'objects' : [] }
for row in collection:
    relationships = row['relationships']
    
    for rel in relationships:
       samples = db.sample.find({'_id':ObjectId(rel['value'])})
       for sample in samples:
          if sample['mimetype'] not in not_mimetypes:
             data['objects'].append( { 'id' : str(row['_id']), 'ssdeep' : row['value'], 'tags' : row['bucket_list'], 'campaigns' : row['campaign'] } )

final_data = dumps(data)

with open(config.get('global','ssdeep_dir') + "/ssdeep.json", 'w') as outfile:
    outfile.write(final_data)
