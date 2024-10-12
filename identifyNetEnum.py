from random import randint
import tkinter as tk
from tkinter import *
from tkinter import ttk
from datetime import datetime

# Local file imports
import netsysTools

class IdentifyNetEnum:
    def __init__(self, root=None, capturedPackets=None, stdout=None):
        self.root = root
        self.defaultBg = "grey18" # Default background color

        self.capturedPackets = capturedPackets  # List of packets captured using pyshark or other packet capture libraries
        self.streams = {}  # Dictionary to hold packet streams
        self.stream = 0  # Current stream identifier
        self.scan_list = [] # List to store scan results
        self.stdout = stdout # Standard output stream
        self.id = randint(10**(6-1), (10**6)-1) # Generate a random ID for the instance
        self.sendEmailTo = netsysTools.retConfig("email_send_to") # Email address to send notifications to

        self.main() # Automatically call the main method when the class is instantiated


    # Function to setup the style of the GUI
    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')  # Use clam theme
        style.configure("Treeview", background="grey16", fieldbackground="grey18", foreground="white", rowheight=25)
        style.configure("Treeview.Heading", background="grey18", foreground="white")
        style.map("Treeview", background=[('selected', 'grey25')])  # Change selected row color


    # Create the main frame for the treeviews
    def create_frames(self):
        self.frm = Frame(self.window, bg="grey18")
        self.frm.pack(padx=10, pady=10, fill='both', expand=True)


    # Create the treeviews with headings and scrollbars
    def create_treeviews(self):
        self.port_enum, self.port_enum_scrollbar = self.create_treeview("Alerts")

        # Configure scrollbars
        self.port_enum_scrollbar.config(command=self.port_enum.yview)
        self.port_enum.config(yscrollcommand=self.port_enum_scrollbar.set)


    # Create the heading for scan alerts
    def create_treeview(self, label_text):
        # Create frame for each treeview and scrollbar
        frame = Frame(self.frm, bg="grey18")
        frame.pack(padx=(0, 5), pady=(0, 20), fill='both', expand=True)

        tv = ttk.Treeview(frame, columns=(1, 2, 3, 4, 5), show="headings")
        tv.column(1, anchor='center', width=40)  # Align IP Address left
        tv.column(2, anchor='center', width=15)
        tv.column(3, anchor='center', width=15)
        tv.column(4, anchor='center', width=15)
        tv.column(5, anchor='center', width=15)

        tv.heading(1, text="Time", anchor='center')
        tv.heading(2, text="Scan Type", anchor='center')
        tv.heading(3, text="Attacker IP", anchor='center')
        tv.heading(4, text="Port Number", anchor='center')
        tv.heading(5, text="Port Status", anchor='center')

        label = Label(frame, text=label_text, font=("Helvetica", 14), bg="grey18", fg="white")
        label.pack(pady=(0, 5))
        tv.pack(side=LEFT, fill='both', expand=True)

        scrollbar = Scrollbar(frame)
        scrollbar.pack(side=RIGHT, fill='y')

        return tv, scrollbar


    # Clear the treeview and insert new data (refresh the treeview)
    def clear_and_insert(self, tv, data):
        # Clear existing entries
        for item in tv.get_children():
            tv.delete(item)
        
        # Insert new data with padding using labels
        for packettime, scantype, attackerip, portnumber, portstatus in data:
            padded_packettime = f"{packettime}"  # Add leading spaces
            tv.insert('', 'end', values=(padded_packettime, scantype, attackerip, portnumber, portstatus))
    
        # Destroy the root window and shutdown the executor upon closing
    
    
    # Function to handle the closing of the window
    def onClosing(self):
        self.output("STOP") # Close the output stream when the scan is completed
        self.window.destroy()
    
    
    # Function to output messages to the standard output stream
    def output(self, message):
        if self.stdout != None:
            # Check if the stdout is a deque from collections
            if str(type(self.stdout)) == "<class 'collections.deque'>":
                self.stdout.append((f"Enumeration Scanner Output Log - {self.id}", message)) # Append the message to the stdout list
            
            # Check if the stdout is a multiprocessing Queue
            elif str(type(self.stdout)) == "<class 'multiprocessing.queues.Queue'>":
                self.stdout.put((f"Enumeration Scanner Output Log - {self.id}", message))
        else:
            print(message)


    # Function to process packets and group them by stream ID
    def process_packets(self):
        # Loop through captured packets and group them by stream ID
        for packet in self.capturedPackets:
            # Check if the packet is TCP and has a stream
            if 'TCP' in packet:
                self.stream = int(packet.tcp.stream)
                
                # Initialize the stream entry if it doesn't exist
                if self.stream not in self.streams:
                    self.streams[self.stream] = []
                
                # Append the packet to its respective stream
                self.streams[self.stream].append(packet)


    # Function to identify TCP scan
    def identify_tcp_scan(self):
        # Loop through each stream and analyze the packets
        for stream_id, packets in self.streams.items():
            syn_packet = None
            syn_ack_packet = None
            ack_packet = None
            rst_ack_packet = None

            # Iterate over packets in each stream
            for packet in packets:
                # Check for SYN packet (SYN == 1 and ACK == 0)
                if packet.tcp.flags_syn == "True" and packet.tcp.flags_ack == "False":
                    syn_packet = packet
                
                # Check for SYN/ACK packet (SYN == 1 and ACK == 1)
                elif packet.tcp.flags_syn == "True" and packet.tcp.flags_ack == "True":
                    syn_ack_packet = packet

                 # Check for ACK packet (ACK == 1)
                elif packet.tcp.flags_ack == "True" and packet.tcp.flags_syn == "False" and packet.tcp.flags_reset == "False": 
                    ack_packet = packet

                # Check for RST/ACK packet (RST == 1 and ACK == 1)
                elif packet.tcp.flags_reset == "True" and packet.tcp.flags_ack == "True": 
                    rst_ack_packet = packet
            
            # Print the results for this stream if all relevant packets are found
            try:
                if syn_packet and ack_packet and syn_ack_packet and rst_ack_packet:
                    self.scan_list.append((syn_packet.frame_info.time, "TCP Scan", syn_packet.ip.src, syn_packet.tcp.dstport, "OPEN"))
                elif syn_packet and not ack_packet and not syn_ack_packet and rst_ack_packet:
                    self.scan_list.append((syn_packet.frame_info.time, "TCP Scan", syn_packet.ip.src, syn_packet.tcp.dstport, "CLOSE"))
            except:
                continue


    # Function to identify SYN scan
    def identify_syn_scan(self):
        # Loop through each stream and analyze the packets
        for stream_id, packets in self.streams.items():
            syn_packet = None
            syn_ack_packet = None
            rst_packet = None
            rst_ack_packet = None

            # Iterate over packets in each stream
            for packet in packets:
                # Check for SYN packet (SYN == 1 and ACK == 0)
                if packet.tcp.flags_syn == "True" and packet.tcp.flags_ack == "False":
                    syn_packet = packet
                
                # Check for SYN/ACK packet (SYN == 1 and ACK == 1)
                elif packet.tcp.flags_syn == "True" and packet.tcp.flags_ack == "True":
                    syn_ack_packet = packet
                
                # Check for RST packet (RST == 1 and ACK == 0)
                elif packet.tcp.flags_reset == "True" and packet.tcp.flags_ack == "False": 
                    rst_packet = packet
                               
                # Check for RST/ACK packet (RST == 1 and ACK == 0)
                elif packet.tcp.flags_reset == "True" and packet.tcp.flags_ack == "True": 
                    rst_ack_packet = packet
            
            # Print the results for this stream if all relevant packets are found
            try:
                if syn_packet and syn_ack_packet and rst_packet:
                    self.scan_list.append((syn_packet.frame_info.time, "SYN Scan", syn_packet.ip.src, syn_packet.tcp.dstport, "OPEN"))
                elif syn_packet and not syn_ack_packet and not rst_packet and rst_ack_packet:
                    self.scan_list.append((syn_packet.frame_info.time, "SYN Scan", syn_packet.ip.src, syn_packet.tcp.dstport, "CLOSE"))
            except:
                continue


    # Function to identify FIN scan
    def identify_fin_scan(self):
        # Loop through each stream and analyze the packets
        for stream_id, packets in self.streams.items():
            fin_packet = None
            rst_ack_packet = None

            # Iterate over packets in each stream
            for packet in packets:
                # Check for FIN packet (FIN == 1 and PUSH == 0 and URGENT == 0) to prevent confusion with XMAS Scan. 
                if packet.tcp.flags_fin == "True" and packet.tcp.flags_push == "False" and packet.tcp.flags_urg == "False": 
                    fin_packet = packet
                
                # Check for RST/ACK packet (RST == 1 and ACK == 1) 
                elif packet.tcp.flags_reset == "True" and packet.tcp.flags_ack == "True": 
                    rst_ack_packet = packet
            
            # Print the results for this stream if all relevant packets are found
            try:
                if fin_packet and not rst_ack_packet:
                    self.scan_list.append((fin_packet.frame_info.time, "FIN Scan", fin_packet.ip.src, fin_packet.tcp.dstport, "OPEN"))
                else:
                    self.scan_list.append((fin_packet.frame_info.time, "FIN Scan", fin_packet.ip.src, fin_packet.tcp.dstport, "CLOSE"))
            except:
                continue

  
    # Function to identify NULL scan
    def identify_null_scan(self):
        # Loop through each stream and analyze the packets
        for stream_id, packets in self.streams.items():
            null_packet = None
            rst_ack_packet = None

            # Iterate over packets in each stream
            for packet in packets:
                # Check for FIN packet (SYN == 0 and ACK == 0 and RST == 0 and FIN == 0 and PUSH == 0 and URGENT == 0) to ensure there is no flags. 
                if packet.tcp.flags_syn == "False" and packet.tcp.flags_ack == "False" and packet.tcp.flags_reset == "False" and packet.tcp.flags_fin == "False" and packet.tcp.flags_push == "False" and packet.tcp.flags_urg == "False": 
                    null_packet = packet
                
                # Check for RST/ACK packet (RST == 1 and ACK == 1) 
                elif packet.tcp.flags_reset == "True" and packet.tcp.flags_ack == "True": 
                    rst_ack_packet = packet
            
            # Print the results for this stream if all relevant packets are found
            try:
                if null_packet and not rst_ack_packet:
                    self.scan_list.append((null_packet.frame_info.time, "NULL Scan", null_packet.ip.src, null_packet.tcp.dstport, "OPEN"))
                else:
                    self.scan_list.append((null_packet.frame_info.time, "NULL Scan", null_packet.ip.src, null_packet.tcp.dstport, "CLOSE"))
            except:
                continue


    # Function to identify XMAS scan
    def identify_xmas_scan(self):
        # Loop through each stream and analyze the packets
        for stream_id, packets in self.streams.items():
            xmas_packet = None
            rst_ack_packet = None

            # Iterate over packets in each stream
            for packet in packets:
                # Check for XMAS packet (SYN == 0 and ACK == 0 and RST == 0 and FIN == 1 and PUSH == 1 and URGENT == 1). 
                if packet.tcp.flags_syn == "False" and packet.tcp.flags_ack == "False" and packet.tcp.flags_reset == "False" and packet.tcp.flags_fin == "True" and packet.tcp.flags_push == "True" and packet.tcp.flags_urg == "True": 
                    xmas_packet = packet
                
                # Check for RST/ACK packet (RST == 1 and ACK == 1) 
                elif packet.tcp.flags_reset == "True" and packet.tcp.flags_ack == "True": 
                    rst_ack_packet = packet
            
            # Print the results for this stream if all relevant packets are found
            try:
                if xmas_packet and not rst_ack_packet:
                    self.scan_list.append((xmas_packet.frame_info.time, "XMAS Scan", xmas_packet.ip.src, xmas_packet.tcp.dstport, "OPEN"))
                else:
                    self.scan_list.append((xmas_packet.frame_info.time, "XMAS Scan", xmas_packet.ip.src, xmas_packet.tcp.dstport, "CLOSE"))
            except:
                continue

    
        # Send email notification if new unknown devices are found
    
    
    # Main function to start network enumeration scanner
    def identifyNetworkEnumeration(self):
        self.process_packets()  # Process captured packets
        self.identify_tcp_scan()
        self.identify_syn_scan() 
        self.identify_fin_scan()
        self.identify_null_scan()
        self.identify_xmas_scan()

        # Send email notification if enumeration scan is detected
        if self.scan_list:
            netsysTools.sendEmail(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Enumeration detected", f"The enumeration scanner has detected enumeration scan. Check scan results!!", self.sendEmailTo)

        self.scan_list = sorted(self.scan_list, key=lambda x: x[-1], reverse=True) # Sort the scan results by port status
        self.clear_and_insert(self.port_enum,self.scan_list) # Clear and insert the scan results into the treeview


    # Main function to start the GUI
    def main(self):
        self.window = tk.Toplevel(self.root) # Create the root window
        self.window.config(bg=self.defaultBg) # Set the background color
        self.window.geometry("700x800") # Set the window size
        self.window.title("Network Scanner") # Set the window title
        self.window.protocol("WM_DELETE_WINDOW", self.onClosing) # Bind the close event to the close handler

        self.setup_style()
        self.create_frames()
        self.create_treeviews()
        self.identifyNetworkEnumeration()
