import re
import time
import socket
import platform
import subprocess
import numpy as np
from random import randint
from datetime import datetime
import matplotlib.pyplot as plt
from scipy.interpolate import pchip

# Local file imports
import netsysTools

class LatencyTester:
    def __init__(self, host=None, port=80, unreachableHostMaxCounter=None, maxDataSampleSize=None, stdout=None):
        self.host = host # Hostname or IP address to test
        self.port = port # Port number to test
        self.unreachableHostMaxCounter = netsysTools.retConfig("latency_unreachableHostMaxCounter") if not unreachableHostMaxCounter else unreachableHostMaxCounter # Maximum number of times host can be unreachable before exiting
        self.maxDataSampleSize = netsysTools.retConfig("latency_maxDataSampleSize") if not maxDataSampleSize else maxDataSampleSize # Maximum number of data samples to collect (duration of the test = maxDataSampleSize * 0.5 seconds)
        self.unreachableHostCounter = 0 # Counter for unreachable hosts
        self.stdout = stdout # Standard output stream
        self.id = randint(10**(6-1), (10**6)-1) # Generate a random ID for the instance
        self.externalhosts = {
            "Dallas":["dallas.testmy.net", 444],
            "Colorado":["co3.testmy.net", 444],
            "Miami":["fl.testmy.net", 444],
            "New York":["ny.testmy.net", 444],
            "San Francisco":["sf.testmy.net", 444],
            "Los Angeles":["lax.testmy.net", 444],
            "Toronto":["toronto.testmy.net", 444],
            "London":["uk.testmy.net", 444],
            "Germany":["de.testmy.net", 444],
            "Tokyo":["jp.testmy.net", 444],
            "Singapore":["sg.testmy.net", 444],
            "India":["in.testmy.net", 444],
            "Sydney":["au.testmy.net", 444],
            "Chile":["cl.testmy.net", 444],
            "Africa":["za.testmy.net", 444],
            "Mexico":["mx.testmy.net", 444],
            "Google":["google.com", 443],
            "Cloudflare":["cloudflare.com", 443],
            "Facebook":["facebook.com", 443],
            "Amazon":["amazon.com", 443]
            } # Dictionary of test hosts with their respective ports
        self.latencyTest() # Automatically run the latency test when the class is instantiated


    # Return the list of hosts possible for testing
    def get_hosts(self):
        return list(self.externalhosts.keys())


    # Function to output messages to the standard output stream
    def output(self, message):
        if self.stdout != None:
            if str(type(self.stdout)) == "<class 'collections.deque'>": # Check if the stdout is a deque from collections
                self.stdout.append((f"Latency Tester Output Log - {self.id}", message)) # Append the message to the stdout list

            elif str(type(self.stdout)) == "<class 'multiprocessing.queues.Queue'>": # Check if the stdout is a multiprocessing Queue
                self.stdout.put((f"Latency Tester Output Log - {self.id}", message))
        else:
            print(message)


    # Check if the host is a valid IP address/hostname (prevent command injection)
    def is_valid_ip_or_host(self, host):
        # Regular expression for a valid IPv4 address
        ip_pattern = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')
        # Regular expression for a valid hostname
        hostname_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$|^localhost$')

        return bool(ip_pattern.match(host) or hostname_pattern.match(host))


    # Measure TCP latency using a socket connection
    def measure_tcp_latency(self, timeout=4):
        try:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            start_time = time.time() # Measure start time
            sock.connect((self.host, self.port)) # Try to connect to the server
            latency = (time.time() - start_time) * 1000 # Measure end time and calculate latency (ms)
            sock.close()
            self.unreachableHostCounter = 0 # Reset counter if host is reachable
            return latency
        
        # Handle connection timeout error
        except (socket.timeout, ConnectionRefusedError):
            self.output(f"TCP connection to {self.host}:{self.port} failed.")
            self.unreachableHostCounter += 1 # Increment counter if host is unreachable
            return None
        except Exception as e:
            self.output(f"Error: {e}")
            self.unreachableHostCounter += 1 # Increment counter if host is unreachable
            return None


    # Measure ICMP latency using the system's ping command
    def measure_ping_latency(self):
        try:
            # Run the system's ping command (used array to minimise command injection)
            # Check the system's platform to determine the correct ping command
            if platform.system().lower() == "windows":
                output = subprocess.check_output(["ping", self.host, "-n", "1"]).decode()
            else:
                output = subprocess.check_output(["ping", self.host, "-c", "1"]).decode() # For Linux OS and Mac OS

            # Use regex to find the time in ms
            match = re.search(r'time[=<](\d+)\s?ms', output)
            if match:
                self.unreachableHostCounter = 0 # Reset counter if host is reachable
                return int(match.group(1)) # Return first match
            else:
                self.output(f"Failed to parse ping response for {self.host}.")
                self.unreachableHostCounter += 1 # Increment counter if host is unreachable
                return None
        
        # Handle subprocess error if host is unreachable
        except subprocess.CalledProcessError as e:
            self.output(f"Ping to {self.host} failed")
            self.unreachableHostCounter += 1
            return None


    # Process latency data into valid and invalid categories
    def process_latencies(self, latencies, time_num):
        valid_dict = {}
        invalid_dict = {}
        current_val = 0

        # Process latency data into valid and invalid categories for smoothing function
        for i, latency in enumerate(latencies):
            if latency is None:
                # If latency is None, it means the host is unreachable, add it to the invalid dictionary
                if current_val not in invalid_dict:
                    invalid_dict[current_val] = [[], []] # array 1 - latency, array 2 - time
                invalid_dict[current_val][0].append(0)
                invalid_dict[current_val][1].append(time_num[i])
            else:
                # If latency is a valid number, add it to the valid dictionary
                if current_val not in valid_dict:
                    valid_dict[current_val] = [[], []] # array 1 - latency, array 2 - time
                valid_dict[current_val][0].append(latency)
                valid_dict[current_val][1].append(time_num[i])
            
            # Check if the next latency is of a different type (valid/invalid), increment currentVal to start a new segment
            if i + 1 < len(latencies) and type(latency) != type(latencies[i + 1]):
                current_val = i + 1
            
        return valid_dict, invalid_dict


    # Parse data into smoothing function
    def smoothen_data(self, valid_dict, invalid_dict, color, validLabel, invalidLabel, marker='o'):
        # Plot the valid and invalid data
        for x, item in enumerate(valid_dict):
            times = [datetime.fromtimestamp(t) for t in valid_dict[item][1]] # Convert timestamp to datetime object
            latencies = valid_dict[item][0]

            # If there is only one data point, plot it as a scatter point, else interpolate the data
            if len(times) == 1:
                plt.scatter(times, latencies, color=color, label=validLabel if x == 0 else '', marker=marker)
            else:
                # Interpolate the data using pchip interpolation
                pchip_interp = pchip(valid_dict[item][1], valid_dict[item][0]) # array 1 - latency, array 2 - time
                time_interp = np.linspace(valid_dict[item][1][0], valid_dict[item][1][-1], 500)
                lat_interp = pchip_interp(time_interp)
                plt.plot([datetime.fromtimestamp(t) for t in time_interp], lat_interp, color=color, label=validLabel if x == 0 else '')
        
        # Plot the invalid data
        for x, item in enumerate(invalid_dict):
            times = [datetime.fromtimestamp(t) for t in invalid_dict[item][1]]
            latencies = invalid_dict[item][0]
            plt.scatter(times, latencies, color='red', marker='x', label=invalidLabel if x == 0 else '')


    # Plot latency over time
    def plot_latency(self, timeVal, tcp_latencies, icmp_latencies):
        plt.figure(figsize=(10, 5))
        time_num = [t.timestamp() for t in timeVal] # Convert datetime object to timestamp for interpolation

        # Plot the TCP latency data
        if tcp_latencies:
            valid_tcp, invalid_tcp = self.process_latencies(tcp_latencies, time_num)
            self.smoothen_data(valid_tcp, invalid_tcp, color='blue', validLabel='TCP Latency (ms)', invalidLabel='Unreachable TCP')
        
        # Plot the ICMP latency data
        if icmp_latencies:
            valid_icmp, invalid_icmp = self.process_latencies(icmp_latencies, time_num)
            self.smoothen_data(valid_icmp, invalid_icmp, color='green', validLabel='ICMP Latency (ms)', invalidLabel='Unreachable ICMP')
        
        # Set the plot labels and display the plot
        plt.xlabel('Time (HH:MM:SS)')
        plt.ylabel('Latency (ms)')
        plt.title(f'TCP and ICMP Latency Over Time for {self.host}')
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.gcf().canvas.mpl_connect('close_event', self.on_close) # Bind the close event to the close handler
        plt.show()


    # Function to send a stop signal to the output stream when the plot is closed
    def on_close(self, event):
        self.output("STOP")


    # Main latency tester function
    def latencyTest(self):
        # Check if the host is a valid IP address or hostname (prevents command injection)
        if not self.host:
            self.output("STOP")
            return
        if self.host in self.externalhosts:
            self.port = self.externalhosts[self.host][1]
            self.host = self.externalhosts[self.host][0]
        elif not self.is_valid_ip_or_host(self.host):
            self.output("Invalid IP address or hostname.")
            time.sleep(2)
            self.output("STOP")
            return
        
        try:
            if 0 < int(self.port) < 65536:
                self.port = int(self.port)
            else:
                raise ValueError
        except ValueError:
            self.output("Invalid port.")
            time.sleep(2)
            self.output("STOP")
            return

        # Initialize lists to store latency data and time values
        tcp_latencies, icmp_latencies, timeVal = [], [], []

        self.output(f"Testing latency to {self.host} on port {self.port}...")
        self.output(f"Please wait for the test to completes")
        # Collect data for 10 seconds (20 iterations at 0.5 second intervals)
        for x in range(self.maxDataSampleSize):
            timeVal.append(datetime.now()) # Get the current time for tacking latency over time

            # Try to measure TCP latency
            tcp_latency = self.measure_tcp_latency()
            tcp_latencies.append(tcp_latency)

            # Try to measure ICMP latency 
            icmp_latency = self.measure_ping_latency()
            icmp_latencies.append(icmp_latency)

            # If the host is unreachable for X consecutive times, break the loop
            if self.unreachableHostCounter >= self.unreachableHostMaxCounter:
                self.output("Host is unreachable")
                break

            # Display progress in percentage
            self.output(f"Progress: {int(((x+1)/self.maxDataSampleSize) * 100)}%")

            # Wait before sending the next request which is set at 0.5 seconds
            time.sleep(0.5)
        self.output("Scan completed! Loading Data...")

        # Plot the latency over time, with x-axis displaying time and y-axis displaying latency
        try:
            self.plot_latency(timeVal, tcp_latencies, icmp_latencies)
        except Exception(ValueError) as e:
            self.output(f"Error plotting latency data: {e}")