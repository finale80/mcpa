from datetime import datetime, timedelta
import json
from haralyzer import HarParser, HarPage
import harparser
import numpy as np


T_STARTUP = 5.0 #secs


def cumulative_bytes(entries):
    #find init and end times
    global_end_time = 0
    init_time = datetime.strptime(entries[0][u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
    last_byte_ts = 0.0
    selected_entries = []
    for entry in entries:
        #find corresponding domain
        url = entry[u'request'][u'url']
        #NOTE filter suspicious entries
        if "alog" in url or "goupdate" in url or "gofor" in url or "adpush" in url or "goload" in url or "crashlytics" in url or "scorecardresearch" in url or "for-channel" in url:
            continue
        #entry timings
        start_time = datetime.strptime(entry[u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
        start_from_init = (start_time-init_time).seconds + (start_time-init_time).microseconds/1e6
        total_time_secs = entry[u'time']/1e3
        #skip if 0-byte request, 0-byte response (e.g., tls handshake)
        total_bytes = entry[u'request'][u'bodySize'] + entry[u'response'][u'bodySize']
        if total_bytes == 0:
            continue
        #add to subset of valid entries
        selected_entries.append(entry)
        #update end time
        end_from_init = start_from_init + total_time_secs
        if end_from_init > last_byte_ts:
            last_byte_ts = end_from_init
            # print "Last byte ts = " + str(last_byte_ts)
            global_end_time = (datetime.strptime(entry[u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(milliseconds=entry[u'time']))
    #build our cumulate bytes curve
    interval_len =  (global_end_time-init_time).seconds + (global_end_time-init_time).microseconds/1e6
    #print "Interval length (secs) = " + str(interval_len)
    timeline = (np.arange(0.0, interval_len+1e-3, 1e-3)).tolist() # 1ms resolution
    byte_list = [0] * len(timeline)
    percent_list = [0] * len(timeline)
    byte_count = 0
    for entry in selected_entries:
        #entry timings
        start_time = datetime.strptime(entry[u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
        start_from_init = (start_time-init_time).seconds + (start_time-init_time).microseconds/1e6
        total_time_secs = entry[u'time']/1e3
        end_from_init = start_from_init + total_time_secs
        #entry size
        total_bytes = entry[u'request'][u'bodySize'] + entry[u'response'][u'bodySize']
        #skip if 0-byte request, 0-byte response (e.g., tls handshake)
        if total_bytes == 0:
            continue
        byte_count+=total_bytes
        time_counter = 0.0
        pos = 0
        while(time_counter <= start_from_init):
            time_counter+=1e-3
            pos+=1
        while time_counter <= end_from_init:
            byte_list[pos] += total_bytes * ( (time_counter-start_from_init) / total_time_secs )
            pos+=1
            time_counter+=1e-3
            #print byte_list[pos]
        while pos<len(timeline):
            byte_list[pos] += total_bytes
            #print byte_list[pos]
            time_counter+=1e-3
            pos+=1
    #create percentile list
    for i in range(0, len(timeline)):
        percent_list[i] = float(byte_list[i])/byte_count
    return timeline, byte_list



def get_activity_windows_starttimes(app, entries, delta_b, delta_t):
    timeline, cumulate_bytes = cumulative_bytes(entries)
    twin_bytes = 0 #ms
    twin_start = 0 #ms
    twin_end = 0
    activity_windows_start_times = []
    #first, build curve like fig1(b) (using 10 ms step)
    twin_bytes = []
    twin_times = []
    i = 0
    while i < len(timeline):
        twin_bytes.append(cumulate_bytes[twin_end]-cumulate_bytes[twin_start])
        twin_times.append(twin_end*1e-3)
        #twin progress
        if (twin_end-twin_start)+10 > (delta_t*1e3):
            twin_start+=10
            twin_end+=10
        else:
            twin_end+=10
        i+=10 #10ms step
    #check when the curve is above delta_b after delta_t idle period
    y_ref = 0
    y_new = 0
    idle = 0
    start_activity_win = "off" #activity window "state"
    for i in range(len(twin_bytes)):
        y_new = twin_bytes[i]
        if y_new<=y_ref:
            #no activity window found, reset!
            if start_activity_win == "set":
                start_activity_win = "off"
            idle+=10 #+10ms idle
            if idle>(delta_t*1e3):
                start_activity_win = "ready"
        else:
            if start_activity_win == "ready":
                start_activity_win = "set"
                x_start_grow = i*10 #ms
            if y_new>(delta_b*1e3) and start_activity_win == "set" and (x_start_grow*1e-3)>T_STARTUP:
                activity_windows_start_times.append(x_start_grow*1e-3) #sec
                start_activity_win = "off"
            idle = 0
        y_ref = y_new
    return activity_windows_start_times


def get_partition_entries(entries, t_start, t_end):
    selected_entries = []
    init_time = datetime.strptime(entries[0][u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
    for entry in entries:
        start_time = datetime.strptime(entry[u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ")
        start_from_init = (start_time-init_time).seconds + (start_time-init_time).microseconds/1e6
        if start_from_init >= t_start:
            if start_from_init >= t_end:
                break
            selected_entries.append(entry)
    return selected_entries
