import sys
import argparse
import os

import json
from haralyzer import HarParser, HarPage
import harparser

import partitioning
import compute_metrics
import breakdown

MAX_TIME = 1e5
DELTA_B = 5 #KB
DELTA_T = 1.5 #sec

class Parameters :
    pcap=None
    video=None
    critical=None


def ArgumentParsing(this_run):
    parser = argparse.ArgumentParser(description='This script processes an input pcap to extract activity intervals and compute for each partition the critical path')
    parser.add_argument("-p",  "--pcap",   help="Pcap file")
    parser.add_argument("-c",  "--critical",   help="File containing the critical domains sets (optional)")
    args = parser.parse_args()
    if args.pcap:
        this_run.pcap = args.pcap
    else:
    	sys.exit("Error. Missing input pcap file. Check parameters with: python main.py -h")
    if args.critical:
        this_run.critical = args.critical


def get_critical_domains(critical_domains_file, pcap):
    app = pcap.split('/')[-1][0:-5]
    critical_domains_set = []
    try:
        f_in=open(critical_domains_file, 'r')
        critical_domains_set = []
        for line in f_in:
            if app in line:
                critical_domains_set = line[0:-2].split('[')[1].split(' ')
                break
    except:
        print("Unable to parse critical domains sets file")
    if critical_domains_set == []:
        print("\tCritical path is empty (No critical domain)")
    return critical_domains_set


if __name__ == '__main__':
    run = Parameters()
    ArgumentParsing(run)
    pcap = run.pcap
    video = None #analysis of screenrecord disabled

    if run.critical!=None:
        critical_domains_file = run.critical
    else:
        critical_domains_file = None

    #convert pcap file to "HAR"-like representation using our patched version of PcapToHar
    # try:
    #     os.system("./pcap2har_patched/main.py -t 1.5 " + pcap + " " + pcap[0:-5] + ".har > /dev/null")
    # except:
    #     sys.exit("Unable to generate HAR-like representation of input pcap:" + pcap)

    # for each pcap file, the corresponding ".har" is already provided in the example folders
    f_har = open(pcap[0:-5] + ".har", 'r')
    har_parser = HarParser(json.loads(f_har.read()))
    entries = []
    for entry in har_parser.har_data['entries']:
        entries.append(entry)
    sorted_entries = sorted(entries, key=lambda x:x[u'startedDateTime'])

    #get set of critical domains
    if critical_domains_file!=None:
        critical_domains_set = get_critical_domains(critical_domains_file, pcap)

    #send entries to partitioning engine to estimate the activity intervals
    partition_times = partitioning.get_activity_windows_starttimes(pcap[0:-5], sorted_entries, DELTA_B, DELTA_T)

    #isolate entries related to each partition
    per_interval_partitions = []
    if partition_times == []:
        #single parition
        per_interval_partitions = [sorted_entries]
    else:
        #multiple partitions
        first_partition = partitioning.get_partition_entries(sorted_entries, 0.0, partition_times[0])
        per_interval_partitions.append(first_partition)
        for i in range(0,len(partition_times)-1):
            curr_partition = partitioning.get_partition_entries(sorted_entries, partition_times[i], partition_times[i+1])
            per_interval_partitions.append(curr_partition)
        last_partition = partitioning.get_partition_entries(sorted_entries, partition_times[-1], MAX_TIME)
        per_interval_partitions.append(last_partition)

    print("\nNumber of partitions (activity windows) found: %d" % (1+len(partition_times)))
    print("\tActivity_Window 0; t_start = 0.0s")
    for i in range(0, len(partition_times)):
        print("\tActivity_Window %d; t_start = %fs" % (i+1, partition_times[i]))


    #process partitions individually
    for i in range (0, len(per_interval_partitions)):
        if per_interval_partitions[i] == []:
            print("\tActivity_Window %d looks empty! Skipping.." % i)
            continue
        print("\n*** Activity_Window %d ***" % i)

        #compute TDT (and AFT if video available) metrics
        tdt, filtered_entries = compute_metrics.compute_tdt(per_interval_partitions[i], None)
        if video!=None:
            compute_metrics.compute_aft(video)

        #produce per-partition statistics and Time break (for all traffic, including critical path)
        volume, traffic_duration, urls = breakdown.get_breakdown(filtered_entries, [])

        #analyze critical path (if application/partition found in the "critical domains sets" file)
        if critical_domains_file!=None:

            #compute critical path statistics and Time break
            critical_volume, critical_traffic_duration, critical_urls = breakdown.get_breakdown(filtered_entries, critical_domains_set)

            #critical path vs total traffic (summary)
            print("\tCritical path contains: %f percent traffic-volume; %f percent flows" %
                                            ( (critical_volume*1e2)/volume,
                                            (len(critical_urls)*1e2)/len(urls) ))
            print("\tTime on cp = %f (%f percent)" % (critical_traffic_duration, (critical_traffic_duration*1e2)/traffic_duration))
