import socket
import psutil
import numpy as np
from random import randint
from matplotlib import pyplot as plt

class PortMapper:
    def __init__(self, capturedPackets=None, interface="WiFi", stdout=None):
        self.capturedPackets = capturedPackets # List of packets captured using pyshark or other packet capture libraries
        self.stdout = stdout # Standard output stream
        self.interface = interface # Network interface to sniff traffic from
        self.portsCount = [] # List to store port numbers and their count
        self.portsName = [] # List to store port names
        self.myIP = None # Local IP address of the machine
        self.id = randint(10**(6-1), (10**6)-1) # Generate a random ID for the instance
        self.portMapper() # Automatically call the portMapper method when the class is instantiated
    

    # Function to output messages to the standard output streams
    def output(self, message):
        if self.stdout != None:
            if str(type(self.stdout)) == "<class 'collections.deque'>": # Check if the stdout is a deque from collections
                self.stdout.append((f"Port Analysis Output Log - {self.id}", message)) # Append the message to the stdout list

            elif str(type(self.stdout)) == "<class 'multiprocessing.queues.Queue'>": # Check if the stdout is a multiprocessing Queue
                self.stdout.put((f"Port Analysis Output Log - {self.id}", message))
        else:
            print(message)


    # Method to get the local IP address
    def get_local_ip(self):
        addrs = psutil.net_if_addrs() # Get network interface details using psutil
        
        # Check if the interface exists in the list
        if self.interface in addrs:
            # Loop through the list of network data for the selected interface
            for addr in addrs[self.interface]:
                # Check if it's an IPv4 address
                if addr.family == socket.AF_INET:
                    self.myIP = addr.address
                    return
                
        # alternative method to get local IP address if above method fails via socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.myIP = s.getsockname()[0]
        s.close()


    # Method to process packets and extract port information
    def process_packets(self):

        # Loop through captured packets to extract port information
        for packet in self.capturedPackets:
            # Check if the packet has an IP layer
            if 'IP' in packet:
                
                # self.myIP is required to check if local ip is neccessary for a filter as it can be imported file
                if self.myIP:
                    # Check if the packet's source is from the current machine (filter off incoming packets)
                    if self.myIP == packet.ip.src:
                        # Extract the destination port based on TCP or UDP layer
                        if 'TCP' in packet:
                            packetPort = packet.tcp.dstport
                        elif 'UDP' in packet:
                            packetPort = packet.udp.dstport
                else:
                    # Extract the destination port based on TCP or UDP layer
                    if 'TCP' in packet:
                        packetPort = packet.tcp.dstport
                    elif 'UDP' in packet:
                        packetPort = packet.udp.dstport

                    # Handle only well-known ports (below 1024)
                    if 'TCP' in packet or 'UDP' in packet:
                        # Only track well-known destination ports (below 1024)
                        if int(packetPort) < 1024:
                            try:
                                # Map the port numbers to their names (service names like HTTP, FTP)
                                portType = socket.getservbyport(int(packetPort))
                            except:
                                continue
                            if portType not in self.portsName:
                                # Add new port to the list and initialize count
                                self.portsName.append(portType)
                                self.portsCount.append(1)
                            else:
                                # Increment count for existing port
                                self.portsCount[self.portsName.index(portType)] += 1
                        else:
                            # Add a placeholder for other ports
                            if "Others" not in self.portsName:
                                self.portsName.append("Others")
                                self.portsCount.append(1)
                            else:
                                # Increment count for other ports
                                self.portsCount[self.portsName.index("Others")] += 1


    # Method to visualize port usage as a pie chart
    def visualize_port_distribution(self):

        # Explode the data
        explode = [0.05] * len(self.portsName)
        
        # Wedge properties for the pie chart (set edge color to green)
        wp = {'linewidth': 1, 'edgecolor': "green"}

        # Function to calculate percentage and absolute count for pie chart labels
        def percenter(pct, portsCount):
            absolute = int(pct / 100. * np.sum(portsCount))
            return "{:.1f}%\n({:d})".format(pct, absolute)

        # Create pie chart for port usage
        fig, ax = plt.subplots(figsize=(10, 7))

        # Plot the pie chart with the specified properties
        wedges, texts, autotexts = ax.pie(self.portsCount,
                                        autopct=lambda pct: percenter(pct, self.portsCount),
                                        explode=explode,
                                        labels=self.portsName,
                                        startangle=90,
                                        wedgeprops=wp,
                                        textprops=dict(color="black"))

        # Add a legend to the pie chart for clarity
        ax.legend(wedges, self.portsName, title="Ports", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
            
        #Create outline between each piechart
        for w in wedges:
            w.set_linewidth(1)
            w.set_edgecolor('black')

        # Customize and display the pie chart label properties
        plt.setp(autotexts, size=10, weight="bold")
        ax.set_title("Port Distribution Pie Chart")
        plt.tight_layout()
        plt.gcf().canvas.mpl_connect('close_event', self.on_close) # Bind the close event to the close handler
        plt.show()


    # Function to send a stop signal to the output stream when the plot is closed
    def on_close(self, event):
        self.output("STOP")


    # Method to perform the complete port mapping and visualization
    def portMapper(self):
        # Get the local IP address of the machine if data is not a imported file
        if self.interface:
            self.myIP = self.get_local_ip() # Get the local IP address of the machine
        self.process_packets()
        self.visualize_port_distribution()