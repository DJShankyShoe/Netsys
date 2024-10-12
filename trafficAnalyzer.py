import math
import numpy as np
from random import randint
from datetime import datetime
import matplotlib.pyplot as plt

class TrafficAnalyzer:
    def __init__(self, capturedPackets=None, stdout=None):
        self.packets = capturedPackets # List of packets captured using pyshark or other packet capture libraries
        self.stdout = stdout # Standard output stream
        self.packetsMappedSeconds = {} # Dictionary to map seconds to packet count
        self.id = randint(10**(6-1), (10**6)-1) # Generate a random ID for the instance
        self.trafficAnalyzer() # Automatically call the trafficAnalyzer method when the class is instantiated


    # Function to output messages to the standard output stream
    def output(self, message):
        if self.stdout != None:
            # Check if the stdout is a deque from collections
            if str(type(self.stdout)) == "<class 'collections.deque'>":
                self.stdout.append((f"Traffic Analyzer Output Log - {self.id}", message)) # Append the message to the stdout list
            
            # Check if the stdout is a multiprocessing Queue
            elif str(type(self.stdout)) == "<class 'multiprocessing.queues.Queue'>":
                self.stdout.put((f"Traffic Analyzer  Output Log - {self.id}", message))
        else:
            print(message)


    # Function to process packets and map them to seconds
    def process_packet(self, packet):
        # Extract the timestamp (epoch time) of the packet. Round to 2 decimal places for better visualization
        curtime = round(float(packet.frame_info.time_epoch), 2)

        # Validate if the timestamp is already in the dictionary else add it
        if curtime in self.packetsMappedSeconds:
            self.packetsMappedSeconds[curtime] += 1  # Increment the count of packets for the current timestamp
        else:
            self.packetsMappedSeconds[curtime] = 1 # Initialize the count of packets for the current timestamp


    # Function to plot the data
    def plot_data(self):
        plt.figure(figsize=(10, 5))
        
        # Initialize lists for x and y axes
        packetAxis = []
        timeAxis = []

        # Convert timestamps and packet counts to lists
        for time in self.packetsMappedSeconds:
            convertedTime = datetime.fromtimestamp(time).strftime("%H:%M:%S")  # Convert timestamp to HH:MM:SS format
            timeAxis.append(convertedTime)
            packetAxis.append(self.packetsMappedSeconds[time])

        # Determine the splitter for xticks
        if len(self.packetsMappedSeconds.keys()) > 60:
            splitter = math.floor(len(self.packetsMappedSeconds.keys()) / 6) # Split into 6 parts for better readability if duration is greater than 60 seconds
        else:
            splitter = 10  # Default value for less than 60 seconds duration

        indices = np.arange(len(timeAxis)) # Create numeric indices for xticks
        plt.xticks(indices[::splitter], timeAxis[::splitter], rotation=45) # set xticks and rotate for better readability

        # Set the plot labels and display the plot
        plt.plot(indices, packetAxis) # Plot the data
        plt.xlabel('Time (HH:MM:SS)')
        plt.ylabel('No of Packets')
        plt.title('Packets Over Time')
        plt.grid(True)
        plt.tight_layout()
        plt.gcf().canvas.mpl_connect('close_event', self.on_close) # Bind the close event to the close handler
        plt.show()


    # Function to send a stop signal to the output stream when the plot is closed
    def on_close(self, event):
        self.output("STOP")


    # Main function to analyze packets and plot the data
    def trafficAnalyzer(self):
        for packet in self.packets:
            self.process_packet(packet)
        self.plot_data()