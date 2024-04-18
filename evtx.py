#!/usr/bin/env python

import argparse
import Evtx.Evtx as evtx
import json
import xmltodict
from lxml import etree
from tqdm import tqdm
from Evtx.Views import evtx_file_xml_view

def main(args):
    parser = argparse.ArgumentParser(
        prog='evtx Security Log Analyzer',
        description="Analize evtx security logs files")
    parser.add_argument('logfile', type=str, help='Path of the evtx file')
    parser.add_argument('-el', '--eventIDs', nargs='*', type=comma_separated_list, help='Comma separated list of event ids.')
    parser.add_argument('-fl', '--fields', nargs='*', type=comma_separated_list, help='List comma separated fields for use with the list of event ids.')
    parser.add_argument('-i', '--info', action='store_true', help='Show the header of the logfile')
    parser.add_argument('-e', '--event', action='store_true', help='Count Event IDs in the logfile')

    args = parser.parse_args()

    # If fields were provided, but no IDs, we generate an error.
    if args.fields and not args.eventIDs:
        parser.error("-fl|--fields can only be used with -el|--eventsIDs")
    # If only IDs are provided, but no fields, we assign empty names to the fields.
    if args.eventIDs and not args.fields:
        args.fields = ['']
    if args.info:
        info(args.logfile)
    if args.event:
        countIDs(args.logfile)
    if args.eventIDs:
        eventIDs(args.logfile, args.eventIDs[0], args.fields[0])

def get_events(input_file):
    with evtx.Evtx(input_file) as event_log:
        for record in tqdm(event_log.records(), total=len(list(event_log.records())), desc="Loading events"):
            yield record.lxml()

def percentage(number, total):
    if total != 0 :
        return number * 100 / total

def countIDs(logfile):
    from collections import Counter

    interestingID = {'1100':'The event logging service has shut down','1102':'The audit log was cleared',
                    '4624':'An account was successfully logged on','4625':'An account failed to log on',
                    '4634':'An account was logged off','4648':'A logon was attempted using explicit credentials',
                    '4720':'A user account was created','4740':'A user account was locked out',
                    '4672':'Special privileges assigned to new logon'}
    event_data = get_events(logfile)
    ids = []
    total = 0
    for evt in event_data:
        system_tag = evt.find("System", evt.nsmap)
        event_id = system_tag.find("EventID", evt.nsmap)
        ids.append(event_id.text)
        total = total + 1
    logonIDs = Counter(ids).most_common()
    print("Event ID\tCount\tDescription")
    print("--------\t-----\t-----------")    
    for id in logonIDs:
        print("%s (%.2f %%)" %  (id[0],percentage(id[1],total)),"\t",id[1],"\t",(interestingID.get(id[0])))

def filter(event_data,eventIDs,fields=None):
    filtered_events = { }
    for evt in event_data:
        system_tag = evt.find("System", evt.nsmap)
        correlation = system_tag.find("EventRecordID", evt.nsmap)
        event_id = system_tag.find("EventID", evt.nsmap)
        if event_id.text in eventIDs:
            event_data = evt.find("EventData", evt.nsmap)
            event = {}          
            for data in event_data.getchildren():
                if not fields or data.attrib["Name"] in fields:
                    # If we don't have a specified field filter list, print all
                    # Otherwise filter for only those fields within the list
                    event[data.attrib["Name"]] = data.text
            filtered_events[correlation.text] = event
    return filtered_events

def eventIDs(logfile,eventIDs,fields):
    event_data = get_events(logfile)
    filtered = filter(event_data, eventIDs, fields)
    try:
        print(json.dumps(filtered, indent=3))
    except TypeError as e:
        print(f'Error: {e}')

def info(logfile):
    with evtx.Evtx(logfile) as log:
        fh = log.get_file_header()
        print("Header information")
        print(("Format version  : %d.%d" % (fh.major_version(),
                                            fh.minor_version())))
        state = "clean"
        if fh.is_dirty():
            state = "dirty"
        print(("File is         : %s" % (state)))
        full_string = "no"
        if fh.is_full():
            full_string = "yes"
        print(("Log is full     : %s" % (full_string)))
        print(("Current chunk   : %d of %d" % (fh.current_chunk_number(),
                                               fh.chunk_count())))
        print(("Oldest chunk    : %d" % (fh.oldest_chunk() + 1)))
        print(("Next record#    : %d" % (fh.next_record_number())))
        print("")

def comma_separated_list(value):
    return [val.strip() for val in value.split(',')]

if __name__ == "__main__":
    main()
