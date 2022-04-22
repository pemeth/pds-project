import argparse
from cgitb import small
import numpy as np
import pickle
import sys

from lib import *

#-#-#-#-#-#-#-#-#-#-#
 #        MAIN       #
  #-#-#-#-#-#-#-#-#-#-#

parser = argparse.ArgumentParser()
parser.add_argument('-s', nargs=1, help="parse an input pcap file and output 2 csv files with time data split between master / slave")
parser.add_argument('-a', nargs=2, help="analyze and generate a model based on 2 input csv files in the order master slave")
args = parser.parse_args()

if len(sys.argv) < 2:
    print("Program requires exactly one option.")
    parser.print_help()
    exit(1)

if args.s:
    save_csv_data(args.s[0], "master.csv", "slave.csv")
    exit(0)


master = {}
slave = {}

######      ######
# Get the times of packets relative to the start of the communication
master['times'], slave['times'] = load_csv_data(args.a[0], args.a[1], 0.66)

######      ######
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

######      ######
# Get time deltas and window sizes
master['deltas'] = time_deltas(master['times'])
master['window_sizes'] = window_sizes(master['windows'])

slave['deltas'] = time_deltas(slave['times'])
slave['window_sizes'] = window_sizes(slave['windows'])

######      ######
# Split deltas to window sizes
master['deltas_windowed'] = split_deltas_by_window_sizes(master['deltas'], master['window_sizes'])
slave['deltas_windowed'] = split_deltas_by_window_sizes(slave['deltas'], slave['window_sizes'])

print("all data windowed...")

######      ######
# Get characteristics
master['q1'], master['q2'], master['q3'] = np.quantile(master['deltas'], [0.25, 0.5, 0.75])
master['mean'] = np.mean(master['deltas'])

slave['q1'], slave['q2'], slave['q3'] = np.quantile(slave['deltas'], [0.25, 0.5, 0.75])
slave['mean'] = np.mean(slave['deltas'])

######      ######
# Get number of packets per window for split points
master['q1_sizes'] = size_characteristics_for_split_point(master['deltas_windowed'], master['q1'])
master['q2_sizes'] = size_characteristics_for_split_point(master['deltas_windowed'], master['q2'])
master['q3_sizes'] = size_characteristics_for_split_point(master['deltas_windowed'], master['q3'])
master['mean_sizes'] = size_characteristics_for_split_point(master['deltas_windowed'], master['mean'])
slave['q1_sizes'] = size_characteristics_for_split_point(slave['deltas_windowed'], slave['q1'])
slave['q2_sizes'] = size_characteristics_for_split_point(slave['deltas_windowed'], slave['q2'])
slave['q3_sizes'] = size_characteristics_for_split_point(slave['deltas_windowed'], slave['q3'])
slave['mean_sizes'] = size_characteristics_for_split_point(slave['deltas_windowed'], slave['mean'])

######      ######
# Get the best split point
master['split_point'] = choose_best_split_point(
    master['q1_sizes'], master['q1'],
    master['q2_sizes'], master['q2'],
    master['q3_sizes'], master['q3'],
    master['mean_sizes'], master['mean']
    )
slave['split_point'] = choose_best_split_point(
    slave['q1_sizes'], slave['q1'],
    slave['q2_sizes'], slave['q2'],
    slave['q3_sizes'], slave['q3'],
    slave['mean_sizes'], slave['mean']
    )

######      ######
# Get number of packets per window for the chosen best split point
master['best_split_sizes'] = size_characteristics_for_split_point(master['deltas_windowed'], master['split_point'])
slave['best_split_sizes'] = size_characteristics_for_split_point(slave['deltas_windowed'], slave['split_point'])

######      ######
# Get the final 4-tuple, that describes the analyzed communication
master_all = {}
master_lt_split = {}
master_geq_split = {}

slave_all = {}
slave_lt_split = {}
slave_geq_split = {}

master_all['mean'] = np.mean(master['best_split_sizes']['all'])
master_all['std'] = np.std(master['best_split_sizes']['all'])
master_lt_split['mean'] = np.mean(master['best_split_sizes']['lt_split'])
master_lt_split['std'] = np.std(master['best_split_sizes']['lt_split'])
master_geq_split['mean'] = np.mean(master['best_split_sizes']['geq_split'])
master_geq_split['std'] = np.std(master['best_split_sizes']['geq_split'])

slave_all['mean'] = np.mean(slave['best_split_sizes']['all'])
slave_all['std'] = np.std(slave['best_split_sizes']['all'])
slave_lt_split['mean'] = np.mean(slave['best_split_sizes']['lt_split'])
slave_lt_split['std'] = np.std(slave['best_split_sizes']['lt_split'])
slave_geq_split['mean'] = np.mean(slave['best_split_sizes']['geq_split'])
slave_geq_split['std'] = np.std(slave['best_split_sizes']['geq_split'])

master_final_tuple = (
    master['split_point'],
    (master_all['mean'] - 3 * master_all['std'], master_all['mean'] + 3 * master_all['std']),
    (master_lt_split['mean'] - 3 * master_lt_split['std'], master_lt_split['mean'] + 3 * master_lt_split['std']),
    (master_geq_split['mean'] - 3 * master_geq_split['std'], master_geq_split['mean'] + 3 * master_geq_split['std'])
)

slave_final_tuple = (
    slave['split_point'],
    (slave_all['mean'] - 3 * slave_all['std'], slave_all['mean'] + 3 * slave_all['std']),
    (slave_lt_split['mean'] - 3 * slave_lt_split['std'], slave_lt_split['mean'] + 3 * slave_lt_split['std']),
    (slave_geq_split['mean'] - 3 * slave_geq_split['std'], slave_geq_split['mean'] + 3 * slave_geq_split['std'])
)

with open("master_model.pkl", "wb") as f:
    pickle.dump(master_final_tuple, f)

with open("slave_model.pkl", "wb") as f:
    pickle.dump(slave_final_tuple, f)

plot(
    master['best_split_sizes']['all'],
    master['best_split_sizes']['lt_split'],
    master['best_split_sizes']['geq_split'],
    master_final_tuple,
    "Master-To-Slave"
    )
plt.show()
plt.clf()
plot(
    slave['best_split_sizes']['all'],
    slave['best_split_sizes']['lt_split'],
    slave['best_split_sizes']['geq_split'],
    slave_final_tuple,
    "Slave-To-Master"
    )
plt.show()
