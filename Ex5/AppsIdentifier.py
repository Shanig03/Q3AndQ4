import pyshark
import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder

# Generate a unique flow ID based on 5-tuple (source IP, destination IP, source port, destination port, protocol)
def extract_flow_id(packet):
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        protocol = packet.transport_layer
        flow_id = f"{src_ip}_{dst_ip}_{src_port}_{dst_port}_{protocol}"
        return flow_id
    except AttributeError:
        return None

# Calculate the time difference between the current and previous packet
def extract_time_diff(packet, prev_time):
    if prev_time is None:
        return 0.0
    return float(packet.sniff_time.timestamp() - prev_time)

# Process a single PCAPNG file and return a DataFrame
def process_pcapng(file_path, app_label):
    cap = pyshark.FileCapture(file_path, keep_packets=False)
    data = []

    prev_time = None

    for packet in cap:
        # Extract flow ID
        flow_id = extract_flow_id(packet)

        # Extract timestamp and packet size
        timestamp = float(packet.sniff_time.timestamp())
        packet_size = int(packet.length)

        # Calculate time difference
        time_diff = extract_time_diff(packet, prev_time)
        prev_time = timestamp

        # Extract protocol
        protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'None'

        # Append data with 'App' column indicating the capture the packet belongs to
        data.append({
            'FlowID': flow_id,
            'Protocol': protocol,
            'Length': packet_size,
            'Time_Diff': time_diff,
            'Timestamp': timestamp,
            'App': app_label  # Add the app label for the packet
        })

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Label encode the 'FlowID' column
    label_encoder = LabelEncoder()
    df['FlowID'] = label_encoder.fit_transform(df['FlowID'].astype(str))  # Encode FlowID as a numeric feature

    return df

# Convert multiple PCAPNG files to CSV and combine them into one CSV file.
def convert_pcapng_to_csv(pcapng_files, output_dir):
    all_data = []

    for pcapng_file in pcapng_files:
        app_label = os.path.splitext(os.path.basename(pcapng_file))[0]  # Extract app label from the file name
        print(f"Processing {pcapng_file}...")

        df = process_pcapng(pcapng_file, app_label)  # Pass the app label
        all_data.append(df)

    # Combine all DataFrames into a single DataFrame
    combined_df = pd.concat(all_data, ignore_index=True)

    # Save combined DataFrame to CSV
    output_file = os.path.join(output_dir, "merged_data.csv")
    combined_df.to_csv(output_file, index=False)
    print(f"Data successfully saved to {output_file}")

# Load the dataset from a CSV file
def load_and_prepare_data(file_path):
    return pd.read_csv(file_path)

# Split the dataset into training and testing sets.
def split_data(dataset, features, target):
    X_train, X_test, y_train, y_test = train_test_split(
        dataset[features], dataset[target], test_size=0.2, random_state=42
    )
    return X_train, X_test, y_train, y_test


# Train a Random Forest model
def train_random_forest(X_train, y_train):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

# Evaluate the model and return the accuracy
def evaluate_model(model, X_test, y_test):
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions) * 100
    return predictions, accuracy

# Prepare the data for plotting
def prepare_plot_data(results_df, app_labels):
    actual_counts = results_df["Actual_App"].value_counts().reindex(app_labels, fill_value=0)
    predicted_counts_1 = results_df["Predicted_With_FlowID"].value_counts().reindex(app_labels, fill_value=0)
    predicted_counts_2 = results_df["Predicted_Without_FlowID"].value_counts().reindex(app_labels, fill_value=0)
    return actual_counts, predicted_counts_1, predicted_counts_2

# Plot the bar chart for both options
def plot_results(actual_counts, predicted_counts_1, predicted_counts_2, app_labels):
    x_pos = np.arange(len(app_labels))
    bar_width = 0.4

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # option 1: With flowID
    axes[0].bar(x_pos - bar_width / 2, actual_counts, bar_width, label="Actual", color="#FFB6C1")
    axes[0].bar(x_pos + bar_width / 2, predicted_counts_1, bar_width, label="Predicted", color="#A2C2D1")
    axes[0].set_title("Option 1: FlowID, Packet Size, and Timestamp")

    # option 2: Without flowID
    axes[1].bar(x_pos - bar_width / 2, actual_counts, bar_width, label="Actual", color="#D1C6E1")
    axes[1].bar(x_pos + bar_width / 2, predicted_counts_2, bar_width, label="Predicted", color="#7DDC7D")
    axes[1].set_title("Option 2: Packet Size and Timestamp")

    # Common settings for both plots
    for ax in axes:
        ax.set_xlabel("Applications")
        ax.set_ylabel("Success Rate")
        ax.set_xticks(x_pos)
        ax.set_xticklabels(app_labels, rotation=45, ha="right")
        ax.legend()
        ax.grid(axis='y', linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.show()


def main():
    # pcapng files path
    pcapng_files = [
        'firefox.pcapng',
        'google.pcapng',
        'spotify.pcapng',
        'youtube.pcapng',
        'zoom.pcapng'
    ]

    # Output directory for the CSV
    output_dir = 'output'
    os.makedirs(output_dir, exist_ok=True)

    # Convert and combine PCAPNG files into a single CSV
    convert_pcapng_to_csv(pcapng_files, output_dir)

    # Load the dataset (the CSV) after conversion
    dataset_file = os.path.join(output_dir, "merged_data.csv")
    dataset = load_and_prepare_data(dataset_file)

    # Apply one-hot encoding to the 'Protocol' column so that it can be used by machine learning
    dataset = pd.get_dummies(dataset, columns=['Protocol'], drop_first=True)

    # Feature columns and target
    option_one_features = ["Length", "Time_Diff", "FlowID"] + [col for col in dataset.columns if col.startswith('Protocol_')]
    option_two_features = ["Length", "Time_Diff"]
    target_column = "App"

    # Split data for both feature sets
    X_train_1, X_test_1, y_train_1, y_test_1 = split_data(dataset, option_one_features, target_column)
    X_train_2, X_test_2, y_train_2, y_test_2 = split_data(dataset, option_two_features, target_column)

    # Train models for both feature sets
    model_with_flow_id = train_random_forest(X_train_1, y_train_1)
    model_without_flow_id = train_random_forest(X_train_2, y_train_2)

    # Evaluate both models
    predictions_1, accuracy_1 = evaluate_model(model_with_flow_id, X_test_1, y_test_1)
    predictions_2, accuracy_2 = evaluate_model(model_without_flow_id, X_test_2, y_test_2)

    print(f"Accuracy With FlowID: {accuracy_1:.2f}%")
    print(f"Accuracy Without FlowID: {accuracy_2:.2f}%")

    # Prepare results dataframe for plotting
    results_df = X_test_1.copy()
    results_df["Actual_App"] = y_test_1
    results_df["Predicted_With_FlowID"] = predictions_1
    results_df["Predicted_Without_FlowID"] = predictions_2

    # Save prediction results
    results_df.to_csv("results.csv", index=False)

    # Get unique app names
    app_labels = results_df["Actual_App"].unique()

    # Prepare data for the plot
    actual_counts, predicted_counts_1, predicted_counts_2 = prepare_plot_data(results_df, app_labels)

    # Plot the results
    plot_results(actual_counts, predicted_counts_1, predicted_counts_2, app_labels)


# Run the main function
if __name__ == "__main__":
    main()
