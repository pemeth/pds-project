# Author : Patrik Nemeth (xnemet04)
# Email  : xnemet04@stud.fit.vutbr.cz

import pickle
import numpy as np

from lib import time_deltas, window_sizes, split_deltas_by_window_sizes, \
    size_characteristics_for_split_point

def validation_simple(data, model):
    split_time, all_range, lt_range, geq_range = model

    all_sizes = data['best_split_sizes']['all']
    lt_sizes = data['best_split_sizes']['lt_split']
    geq_sizes = data['best_split_sizes']['geq_split']

    print("\ttotal window count: ", len(all_sizes))

    all_cnt = len(all_sizes)
    all_false_positive_cnt = 0
    for size in all_sizes:
        if size < all_range[0] or size > all_range[1]:
            all_false_positive_cnt += 1

    print("\tFP: ", all_false_positive_cnt, " @ ", "{0:.4f}%".format(100 - (all_false_positive_cnt / all_cnt) * 100))

    lt_cnt = len(lt_sizes)
    lt_false_positive_cnt = 0
    for size in lt_sizes:
        if size < lt_range[0] or size > lt_range[1]:
            lt_false_positive_cnt += 1

    print("\tFP: ", lt_false_positive_cnt, " @ ", "{0:.4f}%".format(100 - (lt_false_positive_cnt / lt_cnt) * 100))

    geq_cnt = len(geq_sizes)
    geq_false_positive_cnt = 0
    for size in geq_sizes:
        if size < geq_range[0] or size > geq_range[1]:
            geq_false_positive_cnt += 1

    print("\tFP: ", geq_false_positive_cnt, " @ ", "{0:.4f}%".format(100 - (geq_false_positive_cnt / geq_cnt) * 100))


master_model = None
slave_model = None

with open("master_model.pkl", "rb") as f:
    master_model = pickle.load(f)

with open("slave_model.pkl", "rb") as f:
    slave_model = pickle.load(f)

master = {}
slave = {}

# Load the last third of data for detection validation
master['times'] = np.loadtxt("master.csv")
master['times'] = master['times'][int(len(master['times']) * 0.66):]
master['times'] = master['times'] - master['times'][0] # get the data relative to 0

slave['times'] = np.loadtxt("slave.csv")
slave['times'] = slave['times'][int(len(slave['times']) * 0.66):]
slave['times'] = slave['times'] - slave['times'][0] # get the data relative to 0

# Get 5 minute windows
window_in_minutes = 5
window_in_seconds = window_in_minutes * 60

# Master windows
cnt = 1
master['windows'] = [[]]
for t in master['times']:
    if  t <= cnt * window_in_seconds:
        master['windows'][cnt-1].append(t)
    else:
        cnt += 1
        master['windows'].append([])
# Slave windows
cnt = 1
slave['windows'] = [[]]
for t in slave['times']:
    if  t <= cnt * window_in_seconds:
        slave['windows'][cnt-1].append(t)
    else:
        cnt += 1
        slave['windows'].append([])

# Get time deltas and window sizes
master['deltas'] = time_deltas(master['times'])
master['window_sizes'] = window_sizes(master['windows'])

slave['deltas'] = time_deltas(slave['times'])
slave['window_sizes'] = window_sizes(slave['windows'])

# Split deltas to window sizes
master['deltas_windowed'] = split_deltas_by_window_sizes(master['deltas'], master['window_sizes'])
slave['deltas_windowed'] = split_deltas_by_window_sizes(slave['deltas'], slave['window_sizes'])

# Get number of packets per window for the chosen best split point
master['best_split_sizes'] = size_characteristics_for_split_point(master['deltas_windowed'], master_model[0])
slave['best_split_sizes'] = size_characteristics_for_split_point(slave['deltas_windowed'], slave_model[0])

print("Master False Positive Counts")
validation_simple(master, master_model)

print("Slave False Positive Counts")
validation_simple(slave, slave_model)
