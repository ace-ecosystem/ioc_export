#!/usr/bin/env python3
# vim: ts=3:sw=3:et

import argparse
import io
import logging
import logging.config
import os.path
import sys
import json
from datetime import datetime
from datetime import timedelta

from collections import defaultdict
from configparser import ConfigParser

from pysip import Client

config = None

# maps indicator types to string modifiers in the yara rule
string_modifiers = None

def sanitize(ind_type):
   out = ind_type.replace(" ","")
   out = out.replace("-","")
   return out

def get_yara_header(ind_type):
   out = "//rule created automatically with crits intelligence\n"
   out += "rule " + sanitize(ind_type) + "\n"
   out += "{\n"
   out += "strings:\n"
   return out

def get_yara_footer():
   out = "condition:\n"
   out += "   any of them\n"
   out +="}"
   return out

def format_yara_string(tmpstr):
   out = tmpstr.replace("\\","\\\\")
   out = out.replace("\"","\\\"")
   out = out.replace("\n","")
   
   return out

def get_yara_filename(ind_type):
   out = sanitize(ind_type)
   out += ".yar" 
   return os.path.join(config['global']['rule_dir'], out)

def export():
   global config

   try:
      sip_client = Client(config['sip']['end_point'],config['sip']['api_key'],verify=config['sip']['cert'])
      last_modified = datetime.utcnow() - timedelta(minutes=45)
      collection = sip_client.get('indicators?modified_after={}'.format(last_modified.strftime("%Y-%m-%d %H:%M:%S")))
      if collection['_meta']['total_items'] == 0:
          print("no changes: exiting. {}".format(collection))
          sys.exit()
      #indicator_types = db.object_types.find({"active":"on"})
      #indicator_types = db.indicators.distinct( 'type' )
      #indicator_types = ['Address - ipv4-addr', 'Antivirus - Streetname', 'Code - Binary_Code', 'Email - Address', 'Email - Content', 'Email - Subject', 'Email - Xmailer', 'IDS - Streetname', 'Persona', 'String - AutoIt', 'String - EPS',  'String - Java', 'String - JS', 'String - HTML','String - Mach-O','String - Office', 'String - PDF', 'String - PE', 'String - RTF', 'String - SWF', 'String - Windows Shell', 'String - Unix Shell', 'String - VBS', 'URI - Domain Name', 'URI - HTTP - UserAgent', 'URI - URL', 'URI - Path', 'Windows - FileName', 'Windows - FilePath', 'Windows - Hostname', 'Windows - Mutex', 'Windows - Registry', 'Windows - Service','Email Header Field','Email X-Originating IP']
     
      indicator_types = config['global']['included_types'].split(',')
      allsources = sip_client.get('intel/source')
      sources = []
      not_sources = config['sources']['not']
      for src in allsources:
          sources.append(src['value'])
      #   if src['value'] not in not_sources:
      #      sources.append(src['value']) 

      for row in indicator_types:
         #indicator_type = row['type']
         indicator_type = row
         if 'excluded_types' in config['global'] and indicator_type in [x.strip() for x in config['global']['excluded_types'].split(',')]:
            logging.debug("skipping excluded indicator type {0}".format(indicator_type))
            continue

         logging.debug("exporting indicator type {0}".format(indicator_type))
         #import pdb; pdb.set_trace()
         #collection = db.indicators.find({"status":"Analyzed","type":indicator_type,"source.name":{"$in":sources}})
         collection = sip_client.get('indicators?type={}&status={}&not_sources={}&bulk=true'.format(indicator_type,"Analyzed",not_sources))
        
         # does a template file exists for this indicator type?
         template_path = os.path.join(config['global']['template_dir'], '{0}.template'.format(sanitize(indicator_type)))
         if not os.path.exists(template_path):
            template_path = os.path.join(config['global']['template_dir'], 'default.template')

         logging.debug("using template {0} for {1}".format(template_path, indicator_type))

         with open(template_path, 'r') as fp:
            rule = fp.read()

         rule = rule.replace('TEMPLATE_RULE_NAME', '{0}'.format(sanitize(indicator_type)))
         
         special_paths = {"%temp%":["\\windows\\temp","\\temp","\\appdata\\local\\temp","\\local settings\\temp","\\locals~1\\temp" ],
                       "%appdata%":["\\application data","\\appdata\\roaming"],
                       "%programdata%":["\\programdata","\\documents and settings\\all users"],
                       "%programfiles%":["\\program files","\\program files (x86)"],
                       "%systemdrive%":[""],
                       "%system%":["\\windows\\system32","\\windows\\system"]
                      }


         string_data = io.StringIO()
         count = 0
         for item in collection:
            item_id = item['id']
            item_value = item['value']
            if item['type'] == 'Windows - FilePath':
               subindicator = 0
               for path in special_paths:
                  if path.lower() in item['value'].lower():
                     for p_item in special_paths[path]:
                        item_value = item['value'].lower().replace(path,p_item)
                        item_id = str(item['id'])+"_"+str(subindicator)
                        string_data.write('        ${} = "{}" {}\n'.format(item_id, format_yara_string(item_value), string_modifiers[item['type'].lower()]))
                        subindicator+=1
               if subindicator == 0:
                  string_data.write('        ${} = "{}" {}\n'.format(item_id, format_yara_string(item_value), string_modifiers[item['type'].lower()]))

            elif item['type'] == 'Windows - Registry':
               special_reg = ['hkcu\\','hklm\\','hkc\\','hku\\','hkcr\\']
               for reg in special_reg:
                  item_value = item_value.lower().replace(reg,"") #remove the front end of the indicator if it matches our special case
               string_data.write('        ${} = "{}" {}\n'.format(item_id, format_yara_string(item_value), string_modifiers[item['type'].lower()]))

            elif item['type'] == 'URI - URL':
               special = ['http:','https:']
               for url in special:
                   if item_value.startswith(url):
                       item_value = item_value.lower().replace(url,"")
               string_data.write('        ${} = "{}" {}\n'.format(item_id, format_yara_string(item_value), string_modifiers[item['type'].lower()]))

            else:
               string_data.write('        ${} = "{}" {}\n'.format(item_id, format_yara_string(item_value), string_modifiers[item['type'].lower()]))

            count += 1

         output_file = get_yara_filename(indicator_type)
         with open(output_file, 'w') as fp:
            fp.write(rule.replace('TEMPLATE_STRINGS', string_data.getvalue()))

         logging.info("exported {0} indicators of type {1} to {2}".format(count, indicator_type, output_file))
         if count == 0:
            logging.warning("no strings were exported for {0}, removing {1}".format(indicator_type, output_file))
            try:
               os.remove(output_file)
            except Exception as e:
               logging.error("unable to remove {0}: {1}".format(output_file, str(e)))

   finally:
      print("done")#connection.close()

if __name__ == "__main__":
   parser = argparse.ArgumentParser(description="Exports indicators into yara rules grouped by type.")
   parser.add_argument('-c', '--config', default='etc/flight_detect_export.ini', dest='config_path',
      help="Configuration file to load.")
   args = parser.parse_args()

   # load configuration
   config = ConfigParser()
   config.read(args.config_path)

   # initialize logging
   if not os.path.isdir('logs'):
      os.mkdir('logs')
   logging.config.fileConfig('etc/logging.ini')

   # load string modifiers
   string_modifiers = defaultdict(lambda: config['string_modifiers']['default'])
   for indicator_type in config['string_modifiers']:
      if indicator_type == 'default':
         continue

      string_modifiers[indicator_type] = config['string_modifiers'][indicator_type]
      logging.debug("using string modifiers {} for {}".format(string_modifiers[indicator_type], indicator_type))

   # make sure output directory exists
   if not os.path.isdir(config['global']['rule_dir']):
      try:
         logging.debug("creating rules dir {0}".format(config['global']['rule_dir']))
         os.makedirs(config['global']['rule_dir'])
      except Exception as e:
         logging.error("cannot create rules dir: {0}".format(str(e)))
         sys.exit(1)

   # export the rules
   export()
