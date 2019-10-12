#!/usr/bin/env python
import sys
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib
from requests import get
import argparse

__author__ = 'mustafauzun0'

'''
WATCHSCAN
'''

def md5(file):
    md5Hash = hashlib.md5()
    with open(file, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5Hash.update(chunk)
    return md5Hash.hexdigest()

def virusTotalScan(file):
        checksum = md5(file)
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = { 'apikey': '60d317205ae8f4db3d8c28d0859d42be3cfaf79c176a671f87439783d69d186c', 'resource': checksum }

        try:
            response = get(url, params=params)
            result = response.json()

            if 'scans' in result:
                if result['positives'] > 0:
                    print('Detection ratio: ' + str(result['positives']) + '/' + str(result['total']))
                    print('File: ' + file)
                    print('MD5 Hash: ' + checksum)

        except:
            pass

class EventHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.event_type == 'created' or event.event_type == 'moved':
            if event.is_directory == False:
                if event.event_type == 'moved':
                    file = event.dest_path
                else: 
                    file = event.src_path
                
                virusTotalScan(file)
                

def main():
    parser = argparse.ArgumentParser(description='Watch Folder Scan VirusTotal')
    
    parser.add_argument('-f', '--folder', dest='folder', default='.', type=str, help='Watch Folder')

    args = parser.parse_args()

    path = args.folder

    eventHandler = EventHandler()
    observer = Observer()
    observer.schedule(eventHandler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    main()
