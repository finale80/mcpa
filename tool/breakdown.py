import sys
from datetime import datetime, timedelta
import os
import json
from haralyzer import HarParser, HarPage
import harparser


def get_breakdown(entries, critical_domains):
    urls = set()
    volume = 0.0
    selected_entries = []
    if critical_domains!=[]:
        for entry in entries:
            #only select entries with url in critical_domains
            url = entry[u'request'][u'url']
            curr_dm = None
            for domain in critical_domains:
                if url.split(':')[0]==domain:
                    curr_dm = domain
                    break
            if curr_dm == None and "http://" in url:
                for domain in critical_domains:
                    if domain == url.split("//")[1].split('/')[0]:
                        curr_dm = domain
                        break
            if curr_dm == None:
                continue
            selected_entries.append(entry)
            urls.add(url)
            volume+=entry[u'request'][u'bodySize'] + entry[u'response'][u'bodySize']
    else:
        selected_entries = entries
        for entry in entries:
            urls.add(entry[u'request'][u'url'])
            volume+=entry[u'request'][u'bodySize'] + entry[u'response'][u'bodySize']
    traffic_duration = get_data_exchange_duration(selected_entries)

    #Time Break
    t_total = 0
    t_dns = 0
    t_tcp = 0
    t_tls_quic = 0
    t_data = 0
    for entry in selected_entries:
        t_total += entry[u'time']
        if u'dns' in entry[u'timings']:
            t_dns += max(0, entry[u'timings'][u'dns'])
        if u'connect(quic)' in entry[u'timings']:
            t_tls_quic += entry[u'timings'][u'connect(quic)']
        if u'ssl' in entry[u'timings']:
            t_tls_quic += entry[u'timings'][u'ssl']
        if u'connect' in entry[u'timings']:
            t_tcp += entry[u'timings'][u'connect']
    t_data = t_total - t_dns - t_tcp - t_tls_quic
    #print breakdown results
    if t_total == 0:
        return volume, traffic_duration, urls
    if critical_domains == []:
        print("\tNumber of flows (all) = %d" % len(urls))
        print("\tVolume (all) = %f KB" % (volume/1e3))
        # print"Data exchange time(all traffic)=" + str(traffic_duration) + " seconds"
        print("\tTime-Break (all): DNS=%f; TCP=%f; TLS=%f; DATA=%f" % (t_dns/float(t_total),
                                                                    t_tcp/float(t_total),
                                                                    t_tls_quic/float(t_total),
                                                                    t_data/float(t_total)))
    else:
        if t_total>0:
            #Critical Path
            print("\tNumber of flows (critical-path) = %d" % len(urls))
            print("\tVolume (critical-path) = %f KB" % (volume/1e3))
            # print "Data exchange time(critical path)=" + str(traffic_duration) + " seconds"
            print("\tTime-Break (critical-path): DNS=%f; TCP=%f; TLS=%f; DATA=%f" % (t_dns/float(t_total),
                                                                        t_tcp/float(t_total),
                                                                        t_tls_quic/float(t_total),
                                                                        t_data/float(t_total)))
    return volume, traffic_duration, urls


def get_data_exchange_duration(selected_entries):
    if selected_entries == []:
        return 0.0
    init_time = datetime.strptime(selected_entries[0][u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
    end_time = selected_entries[0][u'time']/1e3
    data_exchange_time = selected_entries[0][u'time']/1e3
    for entry in selected_entries[1:]:
        start_time = datetime.strptime(entry[u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
        start_from_init = (start_time-init_time).seconds + (start_time-init_time).microseconds/1e6

        if start_from_init >= end_time:
            data_exchange_time+=entry[u'time']/1e3
            move_forward = True
        else:
            if start_from_init + entry[u'time']/1e3 > end_time:
                data_exchange_time+= (entry[u'time']/1e3 - (end_time-start_from_init))
                move_forward = True
            else:
                data_exchange_time+=0.0
                move_forward = False
        if move_forward == True:
            end_time = start_from_init + entry[u'time']/1e3
    return data_exchange_time
