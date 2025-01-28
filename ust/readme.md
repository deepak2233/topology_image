# Network Topology and Firewall Analysis

## Overview
This project provides tools for:
1. Generating YAML files from network diagram images.
2. Generating network diagram images from YAML files.
3. Conducting EDA and anomaly detection on firewall logs.

## Features
- **Task 1**: Convert network diagram images into YAML files.
- **Task 2**: Convert YAML files into network diagrams.
- **Task 3**: Perform EDA and anomaly detection on firewall logs, with optional dashboard visualization.

## Requirements
- Python 3.7+
- Libraries: `opencv-python-headless`, `pytesseract`, `yaml`, `networkx`, `matplotlib`, `seaborn`, `scikit-learn`, `streamlit`

## Installation
1. pip install -r requirements.txt

Task 1: Generate YAML from Image

```bash
    python3 main.py generate_yaml --image_path data/bus_top.png --output_path output/network_topology.yaml
```
Task 2: Generate Image from YAML
```bash
    python3 main.py generate_image --yaml_path output/network_topology.yaml --output_path output/network_img.png
```
Task 3: Firewall Log Analysis
```bash
    python3 main.py firewall_analysis --logs_path data/internet_firwall.csv --result_dir output --dashboard
```
## Output
    * Task 1: YAML file representing the network topology.
    * Task 2: Network topology diagram as an image.
    * Task 3: EDA plots, anomaly detection, and optional interactive dashboard.


