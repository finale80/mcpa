import sys
from optparse import OptionParser
from datetime import datetime, timedelta
import os
import json
from haralyzer import HarParser, HarPage
import harparser
import numpy as np

SILENCE_THRESH = 2.0
TDT = 0.95 #95th percentile of bytes cumulative

def compute_aft(path):
    print("\tComputing AFT, input-video=%s ..." % path)
    aft = compute_speed_index_from_video(path, path[0:-4] + ".speedindex.out", path[0:-4] + "_frames")
    aft = max(0.0, aft) #prevent negative in case of incorrect
    return aft


def compute_tdt(entries, silence_thresh):
    print("\tComputing TDT ...")
    if silence_thresh==None:
        silence_thresh=SILENCE_THRESH
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
        #check for Stop, based on silence threshold (TODO: this won't be needed once we have the partitions of the waterfall)
        if start_from_init - last_byte_ts > silence_thresh:
            break
        #add to subset of valid entries
        selected_entries.append(entry)
        #update end time
        end_from_init = start_from_init + total_time_secs
        if end_from_init > last_byte_ts:
            last_byte_ts = end_from_init
            # print "Last byte ts = " + str(last_byte_ts)
            global_end_time = (datetime.strptime(entry[u'startedDateTime'], "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(milliseconds=entry[u'time']))

    #build our ByteIndex (as a CDF)
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

    tdt = None
    #get 99th percentile time
    for i in range(0, len(timeline)):
        if percent_list[i]>=TDT:
            tdt = timeline[i]
            break
    if tdt == None:
        tdt = 0
    print("\tTDT=%f" % tdt)
    return tdt, selected_entries



def compute_speed_index_from_video(video_path, outfile, frames_path):
    # os.system("python ./../visualmetrics.py --video " + video_path + " --screenshot " + video_path + ".png -d frames --notification > " + outfile)
    try:
        os.system("python ./visualmetrics.py --video " + video_path + " -d " + frames_path + " --notification > " + outfile)
    except:
        print("Error while running visualmetrics.py. Skipping")
    with open(outfile) as f:
        lines = f.readlines()
    str_visual_progress = (lines[3].split(": ")[1]).split(", ")
    si_time_secs = []
    si_perc_prog = []
    i=0
    for prog in str_visual_progress:
        #avoid 100% speedindex progress in the middle (speedindex curve not monotonic)
        if int(prog.split('=')[1].split('%')[0])/1e2 == 1.0 and i!=(len(str_visual_progress)-1):
            i+=1
            continue
        si_time_secs.append(int(prog.split('=')[0])/1e3)
        si_perc_prog.append(int(prog.split('=')[1].split('%')[0])/1e2)
        i+=1
    #NOTE repair speedindex progress list if no monotonic (small ripples may appear..)
    ref  = si_perc_prog[0]
    new_si_perc_prog = []
    for item in si_perc_prog:
        if item < ref:
            new_si_perc_prog.append(ref)
        else:
            new_si_perc_prog.append(item)
            ref = item
    #get AFT
    for i in range(0, len(new_si_perc_prog)):
        if new_si_perc_prog[i] == 1.0:
            aft = si_time_secs[i]
    print("\tAFT=%f" % aft)
    return aft
