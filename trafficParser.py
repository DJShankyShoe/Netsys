import time
import pyshark
import asyncio
import keyboard
from random import randint

import pyshark.tshark

# Local file imports
import netsysTools

class TrafficParser:
    def __init__(self, netType="live", pcapFile=None, interface="WiFi", stdout=None, packetProcessor=None, passInterface=False, multiprocess=False, **classArgs):
        self.netType = netType # Type of network traffic to capture (live or pcap)
        self.stdout = stdout # Standard output stream
        self.passInterface = passInterface # Check if the packetProcessor requires an interface variable
        self.packetProcessor = packetProcessor # Function to process captured packets
        self.pcapFile = pcapFile # Path to the pcap file
        self.interface = interface # Network interface to sniff traffic from
        self.multiProcess = multiprocess # Check if the packetProcessor requires a to create process for packetProcessor
        self.stopProcess = False  # Variable to control whether to stop processing
        self.classArgs = classArgs # Additional arguments to pass to the packetProcessor
        self.capturedPackets = [] # List to store captured packets
        self.id = randint(10**(6-1), (10**6)-1) # Generate a random ID for the instance
        self.trafficParser() # Automatically call the trafficParser method when the class is instantiated
    

    # Function to output messages to the standard output stream
    def output(self, message):
        if self.stdout != None:
            # Check if the stdout is a deque from collections
            if str(type(self.stdout)) == "<class 'collections.deque'>":
                self.stdout.append((f"Traffic Parser Output Log - {self.id}", message)) # Append the message to the stdout list
            
            # Check if the stdout is a multiprocessing Queue
            elif str(type(self.stdout)) == "<class 'multiprocessing.queues.Queue'>":
                self.stdout.put((f"Traffic Parser Output Log - {self.id}", message))
        else:
            print(message)


    # Function to toggle stopProcess variable
    def toggle_stopProcess(self):
        self.stopProcess = not self.stopProcess


    # Function to sniff live traffic from a network interface
    def sniffLive(self, path=None):
        self.output(f"Sniffing on interface: {self.interface}")
        self.output("Press ESC to stop sniffing and start processing traffic data\n")
        # Start capturing packets on the specified interface
        capture = pyshark.LiveCapture(interface=self.interface, tshark_path=path)
        
        # Capture packets continuously until 'ESC' is pressed
        for packet in capture.sniff_continuously():
            if self.stopProcess:
                self.output("\nEscape pressed, stopped sniffing...")
                break
            self.capturedPackets.append(packet)  # Store each captured packet
        
        # Close the file capture to free resources
        capture.close()
        self.output(f"Handling {len(self.capturedPackets)} packets. Loading data ...")


    # Function to read and analyze packets from a .pcap file
    def readPcap(self, path=None):
        self.output("\nThis might take a while...")
        self.output("Press ESC to stop processing remaining data\n")

        # Open the .pcap file and start reading packets
        capture = pyshark.FileCapture(self.pcapFile, tshark_path=path)
        # Load packets from the file until 'ESC' is pressed or the file finishes reading
        for count, packet in enumerate(capture):
            if self.stopProcess:
                self.output("\nEscape pressed, stopped reading...")
                break
            self.capturedPackets.append(packet)

            # self.output progress every 500 packets
            if (count % 500) == 0 and count != 0:
                self.output(f"Processed {count} packets...")

        # Close the file capture to free resources
        capture.close()
        self.output(f"Handling {count} packets. Loading data ...")


    # Main method that gets called automatically when an instance is created
    def trafficParser(self):

        # Check if the packetProcessor is a function
        if not callable(self.packetProcessor):
            self.output("packetProcessor must be a callable class")
        else:
            # Register the 'ESC' key to toggle stopProcess variable
            keyboard.add_hotkey('esc', self.toggle_stopProcess)


            # pyshark relies on asyncio to handle tshark in the background, and it requires an event loop. 
            # Normally, the main thread has an event loop
            # But in a ThreadPoolExecutor, the thread doesn’t have one by default since we ran it in a separate thread from another file
            # We fix that by creating and setting a new event loop explicitly.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Depending on the network type, either sniff live traffic or read from a pcap file
            if self.netType == "live":
                try:
                    self.sniffLive(path="tshark\\") # Call the sniffLive function to start capturing packets using created local tshark path
                except pyshark.tshark.tshark.TSharkNotFoundException:
                    try:
                        self.sniffLive() # Call the sniffLive function to start capturing packets using the default tshark path
                    except pyshark.tshark.tshark.TSharkNotFoundException:
                        self.output("TShark not found. Please install wireshark.")
                        time.sleep(4)

            elif self.netType == "pcap":
                try:
                    self.readPcap(path="tshark\\")
                except FileNotFoundError: # Check if the file exists
                    self.output("File not found. Exiting.")
                except pyshark.tshark.tshark.TSharkNotFoundException: # Call the readPcap function to start capturing packets using created local tshark path
                    try:
                        self.readPcap() # Call the readPcap function to start capturing packets using the default tshark path
                    except pyshark.tshark.tshark.TSharkNotFoundException:
                        self.output("TShark not found. Please install wireshark.")
                        time.sleep(4)
            else:
                self.output("Invalid choice. Exiting.")
            
            # Check if the packetProcessor requires a process to be created and if packets were captured (multiProcessing)
            if self.multiProcess and self.capturedPackets:
                if self.passInterface: 
                    self.classArgs['interface'] = self.interface
                
                netsysTools.multiprocesser_executor(self.packetProcessor, capturedPackets=self.capturedPackets, **self.classArgs) # Call the multiprocesser_executor function from the main file to create a process
            
            # Check if any packets were captured before processing (Runs on the main thread)
            elif self.capturedPackets:
                if self.passInterface: # Check if the calling function requires an interface variable
                    self.packetProcessor(capturedPackets=self.capturedPackets, interface=self.interface, stdout=self.stdout, **self.classArgs) # Call processing class here to handle the captured packets
                else:
                    self.packetProcessor(capturedPackets=self.capturedPackets, stdout=self.stdout, **self.classArgs) # Call processing class here to handle the captured packets
            
            self.output("STOP") # Close the output stream
            keyboard.remove_hotkey('esc') # Remove the hotkey after the function completes
