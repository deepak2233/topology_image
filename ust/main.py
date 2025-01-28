import os
import cv2
import pytesseract
import yaml
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import argparse
import streamlit as st

def preprocess_image(image_path):
    print("Preprocessing the image for edge detection...")
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    edges = cv2.Canny(image, 50, 150)
    print("Edge detection completed.")
    return edges

def detect_objects(image):
    print("Detecting objects using OCR...")
    text = pytesseract.image_to_string(image)
    print(f"Detected text: {text}")
    return text

def generate_graph_from_image(image_path):
    print("Generating graph from the image...")
    edges = preprocess_image(image_path)
    detected_text = detect_objects(edges)
    print("Simulating device and link extraction...")
    devices = ["switch1", "server1"]
    links = [("switch1", "server1")]
    graph = nx.DiGraph()
    graph.add_nodes_from(devices)
    graph.add_edges_from(links)
    print("Graph generation completed.")
    return graph

def graph_to_yaml(graph, output_path):
    print("Converting the graph to YAML format...")
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    data = {
        "nodes": [{"id": node, "type": "device", "properties": {"vendor": "Unknown"}} for node in graph.nodes],
        "links": [{"source": u, "target": v, "properties": {"protocol": "TCP"}} for u, v in graph.edges],
    }
    with open(output_path, "w") as file:
        yaml.dump(data, file)
    print(f"YAML file saved at {output_path}.")

def yaml_to_graph(yaml_path):
    print("Loading YAML file to create a graph...")
    with open(yaml_path, "r") as file:
        data = yaml.safe_load(file)
    graph = nx.DiGraph()
    for node in data["nodes"]:
        graph.add_node(node["id"])
    for link in data["links"]:
        graph.add_edge(link["source"], link["target"])
    print("Graph loaded from YAML file.")
    return graph

def visualize_graph(graph, output_path):
    print("Visualizing the graph...")
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, node_color="lightblue", edge_color="black", node_size=2000, font_weight="bold")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels={(u, v): "TCP" for u, v in graph.edges})
    plt.savefig(output_path)
    plt.close()
    print(f"Graph visualization saved at {output_path}.")

def eda_firewall_logs(logs_path, result_dir):
    print("Performing EDA on firewall logs...")
    os.makedirs(result_dir, exist_ok=True)
    logs = pd.read_csv(logs_path)

    print("Generating distribution plots...")
    # Bytes distribution
    plt.figure(figsize=(12, 6))
    sns.histplot(logs['Bytes'], bins=30, kde=True, color='blue')
    plt.title('Distribution of Bytes Transferred')
    plt.xlabel('Bytes')
    plt.ylabel('Frequency')
    bytes_plot_path = os.path.join(result_dir, 'bytes_distribution.png')
    plt.savefig(bytes_plot_path)
    print(f"Bytes distribution plot saved at {bytes_plot_path}")
    plt.close()

    # Packets distribution
    plt.figure(figsize=(12, 6))
    sns.histplot(logs['Packets'], bins=30, kde=True, color='green')
    plt.title('Distribution of Packets')
    plt.xlabel('Packets')
    plt.ylabel('Frequency')
    packets_plot_path = os.path.join(result_dir, 'packets_distribution.png')
    plt.savefig(packets_plot_path)
    print(f"Packets distribution plot saved at {packets_plot_path}")
    plt.close()

    # Correlation heatmap
    print("Generating correlation heatmap...")
    numeric_logs = logs.select_dtypes(include=['number'])
    plt.figure(figsize=(10, 8))
    sns.heatmap(numeric_logs.corr(), annot=True, cmap='coolwarm', fmt='.2f')
    plt.title('Correlation Heatmap')
    heatmap_path = os.path.join(result_dir, 'correlation_heatmap.png')
    plt.savefig(heatmap_path)
    print(f"Correlation heatmap saved at {heatmap_path}")
    plt.close()

    return logs

def detect_anomalies(logs, result_dir):
    print("Detecting anomalies in firewall logs...")
    model = IsolationForest(contamination=0.05, random_state=42)
    logs['Anomaly'] = model.fit_predict(logs.select_dtypes(include=['number']))

    # Anomalies scatter plot
    print("Generating anomalies scatter plot...")
    plt.figure(figsize=(12, 6))
    sns.scatterplot(data=logs, x='Elapsed Time (sec)', y='Bytes', hue='Anomaly', palette={1: 'blue', -1: 'red'})
    plt.title('Anomalies in Bytes vs. Elapsed Time')
    plt.xlabel('Elapsed Time (sec)')
    plt.ylabel('Bytes')
    anomalies_plot_path = os.path.join(result_dir, 'anomalies_scatter_plot.png')
    plt.savefig(anomalies_plot_path)
    print(f"Anomalies scatter plot saved at {anomalies_plot_path}")
    plt.close()

    anomalies = logs[logs['Anomaly'] == -1]
    return logs, anomalies

def calculate_accuracy(logs):
    print("Calculating accuracy of anomaly detection...")
    # Placeholder for actual ground truth labels
    # Replace 'true_labels' with actual labels when available
    true_labels = logs.get('True Label', None)
    if true_labels is not None:
        print("Ground truth labels found. Calculating classification metrics...")
        report = classification_report(true_labels, logs['Anomaly'], target_names=['Normal', 'Anomalous'])
        print("Classification Report:\n", report)
    else:
        print("No ground truth labels provided. Skipping accuracy calculation.")

def firewall_dashboard(logs):
    st.title("Firewall Log Analysis Dashboard")
    
    # Show a sample of the dataset
    st.header("Dataset Overview")
    st.write(logs.head())
    
    # Visualize Bytes distribution
    st.header("Traffic Analysis: Bytes Distribution")
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.histplot(logs['Bytes'], bins=30, kde=True, ax=ax, color='blue')
    ax.set_title("Distribution of Bytes Transferred")
    st.pyplot(fig)
    
    # Anomalies Plot
    st.header("Anomaly Detection")
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.scatterplot(data=logs, x='Elapsed Time (sec)', y='Bytes', hue='Anomaly', palette={1: 'blue', -1: 'red'}, ax=ax)
    ax.set_title("Anomalies in Bytes vs. Elapsed Time")
    st.pyplot(fig)
    
    # Summary Insights
    st.header("Detected Anomalies Summary")
    anomalies = logs[logs['Anomaly'] == -1]
    st.write(f"Total Anomalies Detected: {len(anomalies)}")
    st.write(anomalies)

def main():
    parser = argparse.ArgumentParser(description="Network and Firewall Analysis Tool")
    subparsers = parser.add_subparsers(dest="command", help="Sub-command help")

    # Sub-command for Task 1: Generate YAML from Image
    parser_yaml = subparsers.add_parser("generate_yaml", help="Generate YAML from network diagram image")
    parser_yaml.add_argument("--image_path", required=True, help="Path to the network diagram image")
    parser_yaml.add_argument("--output_path", required=True, help="Path to save the generated YAML file")

    # Sub-command for Task 2: Generate Image from YAML
    parser_image = subparsers.add_parser("generate_image", help="Generate network diagram image from YAML")
    parser_image.add_argument("--yaml_path", required=True, help="Path to the network topology YAML file")
    parser_image.add_argument("--output_path", required=True, help="Path to save the generated image")

    # Sub-command for Task 3: Firewall Log Analysis
    parser_firewall = subparsers.add_parser("firewall_analysis", help="Perform firewall log analysis")
    parser_firewall.add_argument("--logs_path", required=True, help="Path to the firewall logs CSV file")
    parser_firewall.add_argument("--result_dir", required=True, help="Directory to save analysis results")
    parser_firewall.add_argument("--dashboard", action="store_true", help="Run Streamlit dashboard for analysis")

    args = parser.parse_args()

    if args.command == "generate_yaml":
        print("Starting YAML generation from image...")
        graph = generate_graph_from_image(args.image_path)
        graph_to_yaml(graph, args.output_path)

    elif args.command == "generate_image":
        print("Starting image generation from YAML...")
        graph = yaml_to_graph(args.yaml_path)
        visualize_graph(graph, args.output_path)

    elif args.command == "firewall_analysis":
        print("Starting firewall log analysis...")
        logs = eda_firewall_logs(args.logs_path, args.result_dir)
        logs, anomalies = detect_anomalies(logs, args.result_dir)
        calculate_accuracy(logs)  # Added accuracy calculation
        if args.dashboard:
            firewall_dashboard(logs)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
