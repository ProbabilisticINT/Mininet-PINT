# Running PINT on Mininet

This repository gives the sample code to run and test PINT on Mininet.

## Requirements
1. Mininet supporting bmv2 (https://github.com/nsg-ethz/p4-learning)
2. networkx (pip install networkx)
3. scapy (pip install scapy)
4. numpy (pip install numpy)

## Steps to run PINT
- Create topology.

Ensure you are running this in VM with Mininet.
Create a Mininet topology to conduct path tracing on path size N.

`python topo_allocator.py 5`

where 5 indicates that path tracing needs to be conducted on five switches.

- Start Mininet.

Start Mininet with the newly constructed topology.

`sudo p4run --config p4app.json`

- Start path tracing.

Start path tracing by specifying the length of path (N).

`sudo python exp.py 5`

where 5 indicates the length of path.

- Generate results.

Generate results using:

`python generate_results.py 5`

where 5 indicates the length of path. The results can be found under final_results/5. There
will be three files, indicating the average, median and tail number of packets required to conduct
path tracing for path length of 5.

# Running PINT for delay quantiles

## Requirements
1. Python 3.7.5
2. numpy (pip install numpy)

## Steps to run PINT for delay quantiles

- Generate delay data obtained from ns3 simulations.

`python generate_delay_data.py file_name`

where file_name is the location of delay data generated from ns3 simulations. A sample
processed data is present in experiments/delays/processed_data

- Generate results

`python generate_delay_results.py`

This generates the average, median and tail latencies in final_results/delays.
