import numpy as np
from scapy.all import *
from scapy.layers.inet import TCP


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
    plt.plot(sizes_lt_split, label=r"$\Delta t$ < split_point", color="g")
    plt.plot(sizes_geq_split, label=r"$\Delta t$ >= split_point", color="r")

#    plt.axhline(y=model[1][0], color='b', linestyle='--')
#    plt.axhline(y=model[1][1], color='b', linestyle='--')
#
#    plt.axhline(y=model[2][0], color='g', linestyle='--')
#    plt.axhline(y=model[2][1], color='g', linestyle='--')
#
#    plt.axhline(y=model[3][0], color='r', linestyle='--')
#    plt.axhline(y=model[3][1], color='r', linestyle='--')

    if title:
        plt.title(title)

    plt.legend()

def save_csv_data(input: str, output_master: str, output_slave: str):
    """Load pcap data from `input` and save 0-based times to outputs."""
    pkts = rdpcap(input)
    print("pcap file loaded...")

    master_raw = pkts.filter(lambda p: TCP in p and p[TCP].sport == 2404)
    slave_raw = pkts.filter(lambda p: TCP in p and p[TCP].sport == 61254)
    print("data split to master/slave...")

    with open(output_master, "w") as f:
        for pkt in master_raw:
            f.write(str(float(pkt.time - pkts[0].time)) + '\n')

    with open(output_slave, "w") as f:
        for pkt in slave_raw:
            f.write(str(float(pkt.time - pkts[0].time)) + '\n')

def load_csv_data(input_master, input_slave, proportion = 1.0):
    """Load `len(input) * proportion` number of items from csvs `input_master` and `input_slave`."""
    if proportion > 1.0:
        proportion = 1.0
    if proportion < 0.0:
        proportion = 0.0

    master = np.loadtxt(input_master)
    slave = np.loadtxt(input_slave)

    return (master[0:(int(len(master) * proportion))],
            slave[0:(int(len(slave) * proportion))])
