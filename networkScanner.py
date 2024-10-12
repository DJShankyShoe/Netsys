import tkinter as tk
from tkinter import *
from tkinter import messagebox, ttk

import socket
import requests
import netifaces
import ipaddress
import scapy.all as scapy
from dns import resolver, reversename

import threading
import concurrent.futures

import time
import json
import random
from random import randint
from datetime import datetime

import psutil
import subprocess
import winreg as wr

# Local file imports
import netsysTools

class NetworkScanner:
    def __init__(self, root=None, interface=None, max_threads=None, speed="HIGH", timeout=None, replicate=None, api_key=None, stdout=None):
        # GUI
        self.root = root
        self.defaultBg = "grey18" # Default background color
        self.hoverHighlight = "firebrick4" # Color for highlighted row
        self.downHighlight = "grey11" # Color for "Down" status

        # Parameters
        self.interface = interface # Network interface to use for the scan 
        self.max_threads = netsysTools.retConfig("netscan_max_threads") if not max_threads else max_threads # Maximum number of threads to use for the scan
        self.timeout = netsysTools.retConfig("netscan_timeout") if not timeout else timeout # Timeout for each ARP request
        self.replicate = netsysTools.retConfig("netscan_replicate") if not replicate else replicate # Number of times to send arp request to each device per scan
        self.api_key = netsysTools.retConfig("api_key") if not api_key else api_key # API key for maclookup API
        self.speedScan = {"EXTREME": 0, "VERY HIGH": 1, "HIGH": 5, "MEDIUM": 10, "LOW": 20, "VERY LOW": 30, "STEALTH": 120}
        self.speed = self.speedScan[speed] # Speed of scan. The higher the speed, the more prone to detection
        self.stdout = stdout # Standard output stream

        # Process variables
        self.id = randint(10**(6-1), (10**6)-1) # Generate a random ID for the instance
        self.dns_server_ip = "8.8.8.8" # Deafult DNS server if local DNS server cannot be found
        self.lock = threading.Lock()  # Create a lock
        self.sendEmailTo = netsysTools.retConfig("email_send_to") # Email address to send notifications to
        self.mac_lookup_file = "mac_lookup.json" # Dictionary to store the MAC address vendor information as cache
        self.devices_file = "device_list.json" # Dictionary to store the device types on network from previous scans as data
        self.base_unknown = [] # Stores new unkown devices from the scan for email notification

        self.main() # Start the scan
    

    # Style the GUI to dark mode
    def setupStyle(self):
        style = ttk.Style()
        style.theme_use("clam")  # Use clam theme
        style.configure("Treeview", background="grey16", fieldbackground=self.defaultBg, foreground="white", rowheight=25) # Set the style for the treeview
        style.configure("Treeview.Heading", background=self.defaultBg, foreground="white")
        style.map("Treeview", background=[("selected", self.defaultBg)])  # Change selected row color


    # Create the main frame for the treeviews
    def createFrames(self):
        self.frm = Frame(self.window, bg=self.defaultBg)
        self.frm.pack(padx=10, pady=10, fill="both", expand=True)


    # Create the treeviews for known and unknown devices
    def createTreeviews(self):
        self.known_device_tv, self.known_scrollbar = self.createTreeview("Known Devices")
        self.unknown_device_tv, self.unknown_scrollbar = self.createTreeview("Unknown Devices")

        # Configure scrollbars and treeviews
        self.known_scrollbar.config(command=self.known_device_tv.yview)
        self.known_device_tv.config(yscrollcommand=self.known_scrollbar.set) # Attach the scrollbar to the treeview
        self.known_device_tv.bind("<Button-1>", lambda event: self.popUp(event, "unknown")) # Bind right-click event to show popup menu
        self.known_device_tv.bind("<Motion>", self.highlightRow) # Highlight the row under the cursor
        self.known_device_tv.tag_configure("highlight", background=self.hoverHighlight) # Tag for highlighted row
        self.known_device_tv.tag_configure("down", background="grey11") # Tag for "Down" status

        self.unknown_scrollbar.config(command=self.unknown_device_tv.yview)
        self.unknown_device_tv.config(yscrollcommand=self.unknown_scrollbar.set) # Attach the scrollbar to the treeview
        self.unknown_device_tv.bind("<Button-1>", lambda event: self.popUp(event, "known")) # Bind right-click event to show popup menu
        self.unknown_device_tv.bind("<Motion>", self.highlightRow) # Highlight the row under the cursor
        self.unknown_device_tv.tag_configure("highlight", background=self.hoverHighlight) # Tag for highlighted row
        self.unknown_device_tv.tag_configure("down", background=self.downHighlight) # Tag for "Down" status


    # Highlight the row under the cursor by adding a tag
    def highlightRow(self, event):
        tree = event.widget
        item = tree.identify_row(event.y)
        tree.tk.call(tree, "tag", "remove", "highlight")
        tree.tk.call(tree, "tag", "add", "highlight", item)


    # Show a popup menu upon right-click to set the device type
    def popUp(self, event, type):
        # Determine the correct treeview based on the device type
        treeview = self.unknown_device_tv if type == "known" else self.known_device_tv

        # Identify the row under the cursor upon right-click
        iid = treeview.identify_row(event.y)
        if iid:
            values = treeview.item(iid, "values") # Retrieve the values of the selected row

            # Retrieve the IP address and show a confirmation dialog
            ip_address = values[0].strip()
            result = messagebox.askquestion(message=f"Set {ip_address} to {type} device?")

            # If confirmed, update the device type and refresh the treeview
            if result == "yes":
                self.device_data[self.bssid]["Devices"][values[1]]["New Device"] = (type != "known")
                self.dataParser()


    # Create the treeview with headings and scrollbar
    def createTreeview(self, label_text):
        # Create frame for each treeview and scrollbar
        frame = Frame(self.frm, bg=self.defaultBg)
        frame.pack(padx=(0, 5), pady=(0, 20), fill="both", expand=True)

        # Create the treeview with headings
        tv = ttk.Treeview(frame, columns=(1, 2, 3, 4, 5), show="headings", selectmode="browse")
        tv.column(1, anchor="w", width=20)  # Align IP Address left
        tv.column(2, anchor="c", width=20)  # Align MAC Address center
        tv.column(3, anchor="w", width=20)  # Align Hostname left
        tv.column(4, anchor="w", width=100) # Align Vendor left
        tv.column(5, anchor="w", width=20)  # Align Status left
        
        tv.heading(1, text="IP Address", anchor="center")
        tv.heading(2, text="MAC Address", anchor="center")
        tv.heading(3, text=" Hostname", anchor="w")
        tv.heading(4, text=" Vendor", anchor="w")
        tv.heading(5, text="Status", anchor="center")

        # Set the background color of the treeview
        label = Label(frame, text=label_text, font=("Helvetica", 14), bg=self.defaultBg, fg="white")
        label.pack(pady=(0, 5))
        tv.pack(side=LEFT, fill="both", expand=True)

        # Create a scrollbar for the treeview
        scrollbar = Scrollbar(frame)
        scrollbar.pack(side=RIGHT, fill="y")

        return tv, scrollbar


    # Clear the treeview and insert new data (refresh the treeview)
    def clearInsert(self, tv, data):
        # Clear existing entries
        for item in tv.get_children():
            tv.delete(item)
        
        # Insert new data with padding using labels
        for ip, mac, hostname, vendor, status in data:
            ip = " " * 11 + ip # Add leading spaces
            hostname =  " " + hostname # Add leading spaces
            vendor = " " + vendor # Add leading spaces
            status = " " * 12 + status # Add leading spaces
        
            # Assign "down" tag if status is "Down"
            if status.strip() == "Down":
                tv.insert('', 'end', values=(ip, mac, hostname, vendor, status), tags=('down',))
            else:
                tv.insert('', 'end', values=(ip, mac, hostname, vendor, status))


    # Destroy the root window and shutdown the executor upon closing
    def onClosing(self):
        self.output("STOP") # Close the output stream when the scan is completed
        self.run = False # Set the run flag to False to stop the scan
        self.window.destroy()
    

    # Function to output messages to the standard output stream
    def output(self, message):
        if self.stdout != None:
            if str(type(self.stdout)) == "<class 'collections.deque'>": # Check if the stdout is a deque from collections
                self.stdout.append((f"Network Scanner Output Log - {self.id}", message)) # Append the message to the stdout list

            elif str(type(self.stdout)) == "<class 'multiprocessing.queues.Queue'>": # Check if the stdout is a multiprocessing Queue
                self.stdout.put((f"Network Scanner Output Log - {self.id}", message))
        else:
            print(message)
    

    # Retrieve the scan speed value
    def getScanSpeed(self):
        return list(self.speedScan.keys())


    # Retrieve BSSID, SSID and generate a list of IP addresses to scan based on the network range
    def getNetInfo(self):
        self.ip_list = [] # List of IP addresses to scan

        # Get the SSID and BSSID of the connected network on both windows and linux types OS
        try:
            result = subprocess.check_output("netsh wlan show interfaces").decode("utf-8") # Run the command to get network info
            # Extract the SSID and BSSID from the result
            for line in result.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    self.ssid = line.split(":", 1)[1].strip() 
                if "BSSID" in line:
                    self.bssid = line.split(":", 1)[1].strip()

        # Handle the FileNotFoundError exception for Linux OS
        except FileNotFoundError:
            self.ssid = subprocess.check_output("iwgetid -r").decode("utf-8").strip() # Run the command to get the SSID
            self.bssid = subprocess.check_output("iwgetid -r").decode("utf-8").strip() # Run the command to get the BSSID
        
        # Get the IP address and netmask of the specified network interface
        for addr in psutil.net_if_addrs().get(self.interface):
            # Check if the address is an IPv4 address
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                break

        # Generate a list of IP addresses to scan based on the network range
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        self.ip_list = [str(ip) for ip in network.hosts()]

        self.ip_list *= (self.replicate) # Replicate the IP list to increase the number of scans
        random.shuffle(self.ip_list) # Shuffle the IP list to randomize the scan order (reduce detection)

    
    # Get the default gateway IP address from the select network interface (to be used as a DNS server for backup)
    def getGateway(self):
        # Get the default gateway IP address
        self.default_gateway = None
        gateway_info = netifaces.gateways()

        # Verify if the selected interface is among the available interfaces.
        # This distinction is crucial for differentiating between Linux and Windows OS, as they use different naming conventions for network interfaces.
        # Windows OS uses GUIDs for network interfaces, while Linux uses interface names (e.g., "eth0", "wlan0").
        if self.interface not in netifaces.interfaces(): # Windows OS requirement
            # Map GUIDs to interface names in registry
            reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
            reg_key = wr.OpenKey(reg, r"SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}") # Network interfaces registry key
            # Iterate through the network interfaces in the registry to find the interface name
            for guid in netifaces.interfaces():
                try:
                     # Open the registry subkey for the network interface
                    reg_subkey = wr.OpenKey(reg_key, guid + r"\Connection")
                    iface_names = wr.QueryValueEx(reg_subkey, "Name")[0]
                    if iface_names == self.interface: 
                        self.interface = guid 
                        break
                except FileNotFoundError:
                    pass
        
        # Get the default gateway IP address from the gateway_info dictionary (netifaces)
        for key in gateway_info:
            if key != "default" and self.interface in gateway_info[key][0]:
                self.default_gateway = gateway_info[key][0][0]
                break
    

    # Fallback to the default gateway IP address as DNS Server if the DNS server unable to resolve local network hostname
    def setDnsServer(self):
        # Set up the resolver to use a specific DNS server
        dns_resolver = resolver.Resolver()
        dns_ips = dns_resolver.nameservers + [self.default_gateway] # Added the default gateway IP address to the list of DNS servers

        # Iterate through the DNS servers to find the first one that can resolve the local network hostname
        for cur_ip in dns_ips:
            dns_resolver.nameservers = [cur_ip]
            try:
                # Perform reverse DNS lookup on the default gateway IP address (router) as part of testing the DNS server
                reversed_ip = reversename.from_address(self.default_gateway)
                dns_resolver.resolve(reversed_ip, "PTR")
                self.dns_server_ip = cur_ip
                break
            except Exception:
                pass
    
    
    # Perform reverse DNS lookup to get the hostname of an local network IP address
    def reverseDnsLookup(self, ip_address):
        # Set up the resolver to use a specific DNS server
        dns_resolver = resolver.Resolver()
        dns_resolver.nameservers = [self.dns_server_ip]

        try:
            # Perform reverse DNS lookup using DNS server
            reversed_ip = reversename.from_address(ip_address)
            hostname = str(dns_resolver.resolve(reversed_ip, "PTR")[0])
            return hostname
        except Exception:
            return "Unknown"
    

    # Get the device type based on the MAC address using the maclookup API
    def getDeviceType(self, mac_address, api_key=None):
        # Check if the MAC address is already in the cache
        if mac_address[:8] in self.mac_cache:
            return self.mac_cache[mac_address[:8]]
        else:
            # Make a request to the maclookup API to get the device type based on the MAC address
            if api_key:
                url = f"https://api.maclookup.app/v2/macs/{mac_address}/company/name?apiKey={api_key}"
            else:
                url = f"https://api.maclookup.app/v2/macs/{mac_address}/company/name"
            
            response = requests.get(url, timeout=5) # Make a GET request to the API

            # Check if the response is successful
            if response.status_code == 200:
                if response.text == "*NO COMPANY*":
                    return "Unknown"
                elif response.text == "*PRIVATE*":
                    return "Private"
                
                # Update the MAC address cache with the response (Reduce API calls for faster performance)
                with self.lock:  # Acquire the lock before modifying the dict (prevent race condition)
                    self.mac_cache[mac_address[:8]] = response.text
                
                # Save the MAC address cache to a JSON file (IO operation doesn"t require to be locked)
                with open(self.mac_lookup_file, "w") as f:
                    json.dump(self.mac_cache, f, indent=4)

                return response.text  # Adjust based on API response structure
            
            # Handle different response codes
            elif response.status_code == 401:
                return self.getDeviceType(mac_address, api_key=None)
            else:
                return "Unknown (bad req)"
    

    # Perform an ARP scan on the network to discover devices
    def scan(self, ip):
        time.sleep(round(random.uniform(0, self.speed), 3)) # Create a random delay for each scan to reduce detection

        # Create an ARP request packet
        arp_req_frame = scapy.ARP(pdst = ip) # Create an ARP request frame for the specified IP address
        broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") # Create a broadcast Ethernet frame (ARP request are broadcast frames)
        broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame # Combine the Ethernet frame and ARP request frame

        # Send the ARP request and receive the response
        answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = self.timeout, verbose = False)[0]
        
        # Process the response and update the result dictionary
        if answered_list and ip not in self.result:
            mac_addr = answered_list[0][1].hwsrc.upper() # Get the MAC address from the response
            hostname = self.reverseDnsLookup(ip) # Perform reverse DNS lookup to get the hostname
            device_type = self.getDeviceType(mac_addr, self.api_key) # Get the device type based on the MAC address using API

            # Update the result dictionary with the scan result
            with self.lock:  # Acquire the lock before modifying the result (prevent race condition)
                self.result[mac_addr] = [ip, hostname, device_type]

        # Increment the progress counter
        with self.lock: # Acquire the lock before modifying data (prevent race condition)
            self.progress_counter += 1
    

    # Display the progress of the scan
    def progressTracker(self):
        self.output("Loading Scanner, please wait...")

        self.progress_counter = 0 # Counter to track the progress of the scan
        self.progress_precentage = 0 # Progress percentage of scans completed

        while self.progress_counter < len(self.ip_list): # Check if the progress counter is less than the total number of IPs
            cur_progress = round((self.progress_counter / len(self.ip_list)) * 100) # Calculate the current progress percentage

            # Display the progress percentage if it has changed
            if cur_progress != self.progress_precentage:
                self.output(f"Progress: {cur_progress}%") # Display the progress percentage
                self.progress_precentage = cur_progress
            time.sleep(0.3) # Sleep for a short duration to reduce CPU usage and repeated output
        
        # Display a message when the scan is completed
        self.output("Scan completed! Loading Data...")
        self.progress_precentage = "Complete"
    

    # Create threads to perform the scan concurrently
    def threader(self):
        self.result = {} # Dictionary to store the scan results (MAC address, IP, Hostname, Device type) - reset every scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.submit(self.progressTracker) # Start the progress tracker thread
            executor.map(self.scan, self.ip_list) # Start the scan threads with the parsed IP list
    

    # Process the scan results by updating with new values
    def handleResult(self):
        # Check if the BSSID is in the device data dictionary else create a new entry
        # E.g {"<BSSID>": {"SSID": "<Network Name>", "Devices": {"<MAC Address>": {"IP": "<x.x.x.x>", "Hostname": "<hostname>", "Device Type": "<device type>", "New Device": <boolean>, "status": "<status>"}}}}
        if self.bssid not in self.device_data:
            self.device_data[self.bssid] = {"SSID": self.ssid, "Devices": {}}

        # Check if the device is known and update the device list with the scan result
        for cur_device in self.result:
            if cur_device not in self.device_data[self.bssid]["Devices"]:
                self.device_data[self.bssid]["Devices"][cur_device] = {"IP": self.result[cur_device][0], "Hostname": self.result[cur_device][1], "Device Type": self.result[cur_device][2], "New Device": True, "Status": "Up"}
            else:
                temp_device_val = self.device_data[self.bssid]["Devices"][cur_device]["New Device"]
                self.device_data[self.bssid]["Devices"][cur_device] = {"IP": self.result[cur_device][0], "Hostname": self.result[cur_device][1], "Device Type": self.result[cur_device][2], "New Device": temp_device_val, "Status": "Up"}
        
        # Check if the device is down and update the device list with the scan result
        for device in self.device_data[self.bssid]["Devices"]:
            if device not in self.result:
                self.device_data[self.bssid]["Devices"][device]["Status"] = "Down"


    # Saves the data to local JSON file and parses the data to display in the treeviews
    def dataParser(self):
        # Sorts the devices in each BSSID by IP and Status
        for bssid, bssid_data in self.device_data.items():
            devices = bssid_data["Devices"]
            
            # Sort by IP first, then by Status ("Up" should come before "Down")
            sorted_devices = dict(sorted(devices.items(), key=lambda item: ipaddress.IPv4Address(item[1]["IP"]))) # Sort by IP
            sorted_devices = dict(sorted(sorted_devices.items(), key=lambda item: item[1]["Status"], reverse=True)) # Sort by Status
            
            # Update the devices dictionary with sorted devices
            self.device_data[bssid]["Devices"] = sorted_devices
        
        # Save the updated device dictionary to a JSON file
        with open(self.devices_file, "w") as f:
            json.dump(self.device_data, f, indent=4)

        self.known_devices = [] # List of known devices
        self.unknown_devices = [] # List of known devices

        # Extract the known and unknown devices from the device list
        for mac, device_info in self.device_data[self.bssid]["Devices"].items():
            if device_info["New Device"]:
                self.unknown_devices.append((device_info["IP"], mac, device_info["Hostname"], device_info["Device Type"], device_info["Status"])) # Append to the unknown devices list
            else:
                self.known_devices.append((device_info["IP"], mac, device_info["Hostname"], device_info["Device Type"], device_info["Status"])) # Append to the known devices list
        
        self.sendEmail() # Send email notification if new unknown devices are found
        self.clearInsert(self.known_device_tv, self.known_devices) # Populate the known devices treeview
        self.clearInsert(self.unknown_device_tv, self.unknown_devices) # Populate the unknown devices treeview


    # Send email notification if new unknown devices are found
    def sendEmail(self):
        send_email = False # Flag to send email notification
        text = "" # Text to be sent in the email notification with the new unknown devices details
        # Check if the new unknown devices are not in the base unknown list else append to the base unknown list
        for device in self.unknown_devices:
            device = list(device)[:-1] # Remove the status from the device information
            if device not in self.base_unknown:
                self.base_unknown.append(device)
                send_email = True # Set the flag to True if new unknown devices are found
                text += f"IP: {device[0]}, MAC: {device[1]}, Hostname: {device[2]}, Vendor: {device[3]}\n" # Append the device information to the email text
        if send_email:
            # Send email notification if new unknown devices are found
            netsysTools.sendEmail(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: New Unknown Devices Found", f"The network scanner has found new unknown devices on the network.\n\n{text}", self.sendEmailTo)
            self.output("New unkown device - Email notification sent!")


    # Main network scanner function to start the scan properly
    def mainNetworkProcess(self):
        self.run = True # loop condition to keep the scan running
        self.mac_cache = {} # Cache for storing the MAC address vendor information
        self.device_data = {} # Data for storing the device list information from previous scans

        # Load the MAC address cache from a JSON file if exists
        try:
            with open(self.mac_lookup_file, "r") as f:
                self.mac_cache = json.load(f)
        # Create a MAC address cache JSON file if does not exist
        except FileNotFoundError:
            with open(self.mac_lookup_file, "w") as f:
                json.dump(self.mac_cache, f, indent=4)

        # Load the Device lists from a JSON file if exists
        try:
            with open(self.devices_file, "r") as f:
                self.device_data = json.load(f)
        # Create a MAC address cache JSON file if does not exist
        except FileNotFoundError:
            with open(self.devices_file, "w") as f:
                json.dump(self.device_data, f, indent=4)
        
        self.getNetInfo() # Retrieve BSSID, SSID and generate a list of IP addresses to scan based on the network range
        self.getGateway() # Get the default gateway IP address
        self.setDnsServer() # Set the DNS server for use
        while True:
            self.threader() # Perform the scan concurrently using threads
            self.handleResult() # Process the scan results and save the data to a JSON file
            self.dataParser() # Parse the data to display in the treeviews
            
            self.output("Next scan initiating in 60s") # Output message to indicate the scan is being rescanned

            # Refresh rate 60 seconds before rescanning
            for _ in range(60):
                time.sleep(1)
                if not self.run: # Check if the scan should stop
                    return
            
            self.output("Rescanning...")
    

    # Main function to start the network scanner in order
    def main(self):
        if self.interface == None:
            return
        
        self.window = tk.Toplevel(self.root) # Create the root window
        self.window.config(bg=self.defaultBg) # Set the background color
        self.window.geometry("700x800") # Set the window size
        self.window.title("Network Scanner") # Set the window title
        self.window.protocol("WM_DELETE_WINDOW", self.onClosing) # Bind the close event to the close handler

        self.setupStyle()
        self.createFrames()
        self.createTreeviews()
        self.mainNetworkProcess()
