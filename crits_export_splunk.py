#!/usr/bin/env python3
# vim: ts=3:sw=3:et

from pymongo import MongoClient
import argparse
import csv
import logging
import logging.config
import os
import os.path
from configparser import ConfigParser

config = None

# This program exports all Analyzed indicators into a simple csv with columns
# (Indicator_Type, Indicator, CRITS_ObjectID) and the Indicator value is
# wildcarded to enable the splunk lookups to work appropriately on the log source
# fields (so an exact match is not required).  The output of this script is then
# copied to the splunk server and becomes the lookup table all of the
# operationalized splunk searches use.
def get_filename(indtype):
   global config
   out = indtype.replace(" ","")
   out = out.replace("-","")
   out = out.lower()
   out = config['global']['splunk_lookup_table_dir'] + "/" + config['global']['splunk_lookup_table_prefex'] + out + ".csv"
   return out

def export_all_to_splunk():
   global config
   special_paths = {"%temp%":["\\windows\\temp","\\temp","\\appdata\\local\\temp","\\local settings\\temp","\\locals~1\\temp" ], 
                        "%appdata%":["\\application data","\\appdata\\roaming"], 
                        "%programdata%":["\\programdata","\\documents and settings\\all users"], 
                        "%programfiles%":["\\program files","\\program files (x86)"], 
                        "%systemdrive%":[""], 
                        "%system%":["\\windows\\system32","\\windows\\system"]
                       }
   indicator_types = ['Account',
                      'Address - ipv4-addr',
                      'Address - ipv4-net',
                      'Antivirus - Streetname', 
                      'Hash - MD5',
                      'Hash - SHA1',
                      'Hash - SHA256',
                      'Email - Address', 
                      'Email - Subject', 
                      'Email - Xmailer', 
                      'Email X-Originating IP',
                      'IDS - Streetname', 
                      'URI - Domain Name', 
                      'URI - HTTP - UserAgent', 
                      'URI - URL', 
                      'URI - Path', 
                      'Windows - FileName', 
                      'Windows - FilePath', 
                      'Windows - Hostname', 
                      'Windows - Registry', 
                      'Windows - Service',
                      'String - Windows Shell',
                      'String - Unix Shell'
                     ]

   try:
      connection = MongoClient(config['crits']['uri'])
      db = connection[config['crits']['db']]

      allsources = db.indicators.distinct('source.name')
      sources = []
      not_sources = config['sources']['not']
      for src in allsources:
         if src and src not in not_sources:
            sources.append(src)
      print(sources)

      all_filename = get_filename('all_indicators')
      all_f = open(all_filename,'w')
      all_writer = csv.writer(all_f)
      all_writer.writerow(('Indicator_Type','Indicator','ObjectID'))
      for indtype in indicator_types:
         collection = db.indicators.find({"status":"Analyzed",'type':indtype,"source.name":{"$in":sources}})     
         filename = get_filename(indtype)

         logging.info("creating splunk export {0}".format(filename))
         count = 0
         with open(filename, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(('Indicator_Type','Indicator','ObjectID'))
      
            for row in collection:
               if row['type'] == 'Windows - FilePath':
                  for path in special_paths:
                     if path in row['value'].lower():
                        for p_item in special_paths[path]:
                           tmp = row['value'].lower().replace(path,p_item)
                           #print(row['type'],str(tmp),str(row['_id']))
                           writer.writerow((row['type'],str(tmp),str(row['_id'])))
                           all_writer.writerow((row['type'],str(tmp),str(row['_id'])))
                  #replace \ with /
                  tmp = row['value'].lower().replace("\\","/")
                  writer.writerow((row['type'],str(tmp),str(row['_id'])))
                  all_writer.writerow((row['type'],str(tmp),str(row['_id'])))
                  #replace \ with \\
                  tmp = row['value'].lower().replace("\\","\\\\")
                  writer.writerow((row['type'],str(tmp),str(row['_id'])))
                  all_writer.writerow((row['type'],str(tmp),str(row['_id'])))
                  #write it like it is in crits as well (cover all our basis splunk logs can be shit formatted)
                  writer.writerow((row['type'],str(row['value']),str(row['_id'])))
                  all_writer.writerow((row['type'],str(row['value']),str(row['_id'])))

               elif row['type'] == 'Windows - Registry':
                  special_reg = ['hkcu\\','hklm\\','hkc\\','hku\\','hkcr\\']
                  item_value = row['value']
                  for reg in special_reg:
                     item_value = item_value.lower().replace(reg,"") #remove the front end of the indicator if it matches our special case
                  writer.writerow((row['type'],str(item_value),str(row['_id'])))
                  all_writer.writerow((row['type'],str(item_value),str(row['_id'])))
               else:   
                  writer.writerow((row['type'],str(row['value']),str(row['_id'])))
                  all_writer.writerow((row['type'],str(row['value']),str(row['_id'])))
               count += 1

         logging.info("exported {0} indicators".format(count))

   finally:
      try:
         connection.close()
      except:
         pass

if __name__ == "__main__":

   parser = argparse.ArgumentParser(description="Exports CRITS indicators into splunk lookup tables.")
   parser.add_argument('-c', '--config', default='etc/detect_export.ini', dest='config_path',
      help="Configuration file to load.")
   #parser.add_argument('-o', '--out-file', dest='filename', default='all_indicators.csv', required=False, help="Name of the file to create.")
   args = parser.parse_args()

   # load configuration
   config = ConfigParser()
   config.read(args.config_path)

   # initialize logging
   if not os.path.isdir('logs'):
      os.mkdir('logs')
   logging.config.fileConfig('etc/logging.ini')

   export_all_to_splunk()
