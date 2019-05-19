# MCPA (Mobile Traffic Critical Path Analysis)

Open dataset of MCPA paper "Tackling Mobile Traffic Critical Path Analysis With Passive and Active Measurements", to appear in TMA 2019 conference.

## Contents
- *performance_metrics.ipynb*<br/> A Jupyter notebook to display/plot/compare performance indicators (e.g., Page Load Time, Above-the-Fold Time, Trasport Delivery Time, ..) for the mobile apps and webpages used in the paper. Based on the logs in *./performance_metrics*.

- *critical_path_info.ipynb*<br/> A Jupyter notebook summarizing critical path information for the mobile apps used in the paper. Based on data in *./critical_path_info*.

- *waterfall.ipynb*<br/> A Jupyter notebook generating network waterfalls for mobile apps used in the paper. It uses the logs in *./waterfalls*. 

- *./tool*<br/> Part of MCPA code for the processing of pcap mobile-traffic traces. It partitions traffic into activity windows. For each interval, it computes performance metric(s) and reports statistics on the network waterfall and on the Critical Path.

## Getting started with MCPA tool

### Requirements
- Python 2.7+
- Haralyzer (https://pypi.org/project/haralyzer/), Harparser (https://pypi.org/project/harparser/)
- NumPy

### Example (Facebook, app-startup traffic)
```
cd tool/
python main.py -p ./examples_app-startup/com.facebook.katana.pcap -c critical_domains_app-startup.txt 
```
### Arguments

-p : Input pcap file. <br/> Examples can be found in *./tool/examples_app-startup* for app-startup traffic and *./tool/examples_app-click* for app-click traffic

-c : File containing the set of critical domains of the mobile app. <br/> Use *./tool/critical_domains_app-startup.txt* for app-startup traffic and *./tool/critical_domains_app-click.txt* for app-click traffic 
