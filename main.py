import argparse
from cgitb import small
import numpy as np
from scapy.all import *
from scapy.layers.inet import TCP
import sys

def time_deltas(seq: list[float]) -> list[float]:
    deltas = []
    for i in range(1, len(seq)):
        deltas.append(seq[i] - seq[i-1])

    return deltas

def window_sizes(windows: list[list[float]]) -> list[int]:
    sizes = []
    for w in windows:
        sizes.append(len(w))

    return sizes

def split_deltas_by_window_sizes(deltas: list[float], window_sizes: list[int]) -> list[list[float]]:
    split_deltas = []
    start_idx = 0
    for size in window_sizes:
        split_deltas.append(deltas[start_idx:start_idx+size])
        start_idx += size

    return split_deltas

def size_characteristics_for_split_point(delta_windows: list[list[float]], split_point: float) -> dict[str, list[int]]:
    """Returns the number of packets (size) for each window as a list of sizes in a dictionary.
    The dictionary keys are 'all' for all packets, 'lt_split' for packets with delta time less than split point
    and 'geq_split' for packets with delta time greater or equal to split point. """
    n_packets_all = []
    n_packets_lt_split = []
    n_packets_geq_split = []

    for window in delta_windows:
        np_window = np.asarray(window)
        n_packets_all.append(len(np_window))
        n_packets_lt_split.append(len(np_window[np_window < split_point]))
        n_packets_geq_split.append(len(np_window[np_window >= split_point]))

    return {
        'all': n_packets_all,
        'lt_split': n_packets_lt_split,
        'geq_split': n_packets_geq_split
    }

def choose_best_split_point(
    q1_sizes: dict[str, list[int]],
    q1: float,
    q2_sizes: dict[str, list[int]],
    q2: float,
    q3_sizes: dict[str, list[int]],
    q3: float,
    mean_sizes: dict[str, list[int]],
    mean: float
    ) -> float:
    """Returns the best split point"""
    ## Stats for less-than
    q1_n_packets_lt_split = q1_sizes['lt_split']
    q2_n_packets_lt_split = q2_sizes['lt_split']
    q3_n_packets_lt_split = q3_sizes['lt_split']
    mean_n_packets_lt_split = mean_sizes['lt_split']
    q1_lt_mean = np.mean(q1_n_packets_lt_split)
    q2_lt_mean = np.mean(q2_n_packets_lt_split)
    q3_lt_mean = np.mean(q3_n_packets_lt_split)
    mean_lt_mean = np.mean(mean_n_packets_lt_split)
    q1_lt_std = np.std(q1_n_packets_lt_split)
    q2_lt_std = np.std(q2_n_packets_lt_split)
    q3_lt_std = np.std(q3_n_packets_lt_split)
    mean_lt_std = np.std(mean_n_packets_lt_split)

    retval = q1
    smallest_std = q1_lt_std

    if (q2_lt_mean - 3 * q2_lt_std) > 0 and smallest_std > q2_lt_std:
        retval = q2
        smallest_std = q2_lt_std
    if (q3_lt_mean - 3 * q3_lt_std) > 0 and smallest_std > q3_lt_std:
        retval = q3
        smallest_std = q3_lt_std
    if (mean_lt_mean - 3 * mean_lt_std) > 0 and smallest_std > mean_lt_std:
        retval = mean
        smallest_std = mean_lt_std

    ## Stats for greater-or-equal-than
    q1_n_packets_geq_split = q1_sizes['geq_split']
    q2_n_packets_geq_split = q2_sizes['geq_split']
    q3_n_packets_geq_split = q3_sizes['geq_split']
    mean_n_packets_geq_split = mean_sizes['geq_split']
    q1_geq_mean = np.mean(q1_n_packets_geq_split)
    q2_geq_mean = np.mean(q2_n_packets_geq_split)
    q3_geq_mean = np.mean(q3_n_packets_geq_split)
    mean_geq_mean = np.mean(mean_n_packets_geq_split)
    q1_geq_std = np.std(q1_n_packets_geq_split)
    q2_geq_std = np.std(q2_n_packets_geq_split)
    q3_geq_std = np.std(q3_n_packets_geq_split)
    mean_geq_std = np.std(mean_n_packets_geq_split)

    if (q1_geq_mean - 3 * q1_geq_std) > 0 and smallest_std > q1_geq_std:
        retval = q1
        smallest_std = q1_geq_std
    if (q2_geq_mean - 3 * q2_geq_std) > 0 and smallest_std > q2_geq_std:
        retval = q2
        smallest_std = q2_geq_std
    if (q3_geq_mean - 3 * q3_geq_std) > 0 and smallest_std > q3_geq_std:
        retval = q3
        smallest_std = q3_geq_std
    if (mean_geq_mean - 3 * mean_geq_std) > 0 and smallest_std > mean_geq_std:
        retval = mean
        smallest_std = mean_geq_std

    return retval

def plot(sizes_all, sizes_lt_split, sizes_geq_split, model, title=None):
    plt.plot(sizes_all, label="all", color="b")
    plt.plot(sizes_lt_split, label="delta_t < split_point", color="g")
    plt.plot(sizes_geq_split, label="delta_t >= split_point", color="r")

    plt.axhline(y=model[1][0], color='b', linestyle='--')
    plt.axhline(y=model[1][1], color='b', linestyle='--')

    plt.axhline(y=model[2][0], color='g', linestyle='--')
    plt.axhline(y=model[2][1], color='g', linestyle='--')

    plt.axhline(y=model[3][0], color='r', linestyle='--')
    plt.axhline(y=model[3][1], color='r', linestyle='--')

    if title:
        plt.title(title)

    plt.legend()

def save_csv_data(input: str, output_master: str, output_slave: str):
    """Load pcap data from `input` and save 0-based times to outputs."""
    pkts = rdpcap(input)
    print("pcap file loaded...")

    # TODO this might be flipped - figure it out
    master_raw = pkts.filter(lambda p: TCP in p and p[TCP].sport == 61254)
    slave_raw = pkts.filter(lambda p: TCP in p and p[TCP].sport == 2404)
    print("data split to master/slave...")

    with open(output_master, "w") as f:
        for pkt in master_raw:
            f.write(str(float(pkt.time - pkts[0].time)) + '\n')

    with open(output_slave, "w") as f:
        for pkt in slave_raw:
            f.write(str(float(pkt.time - pkts[0].time)) + '\n')

def load_csv_data(input_master, input_slave):
    master = np.loadtxt(input_master)
    slave = np.loadtxt(input_slave)

    return (master, slave)

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
master['times'], slave['times'] = load_csv_data(args.a[0], args.a[1])

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
