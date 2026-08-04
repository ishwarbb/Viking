import re
import subprocess

# Function to parse the output text and extract time values
def parse_output(output):
    times = {}
    matches = re.findall(r'\* (.+?) (\d+\.\d+)(?:ms|µs|s)?', output)
    for match in matches:
        key, value = match
        if key in times:
            times[key].append(float(value))
        else:
            times[key] = [float(value)]
    return times

# Function to calculate average times
def calculate_average(times):
    averages = {}
    for key, value in times.items():
        averages[key] = sum(value) / len(value)
    return averages

# Function to run Rust executable and capture output
def run_rust_executable():
    process = subprocess.Popen(["./target/debug/examples/cubic"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, _ = process.communicate()
    return output.decode("utf-8")

# Run the Rust executable multiple times and capture output
num_runs = 5
total_times = {}
for i in range(num_runs):
    output_text = run_rust_executable()
    parsed_output = parse_output(output_text)
    for key, value in parsed_output.items():
        if key in total_times:
            total_times[key].extend(value)
        else:
            total_times[key] = value

# Calculate average times
average_times = calculate_average(total_times)

# Print the average times in the same format
for key, value in average_times.items():
    print(f"* {key} {value:.6f}ms")
