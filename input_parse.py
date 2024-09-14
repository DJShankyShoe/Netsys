import pyshark
import keyboard
import matplotlib.pyplot as plt
from datetime import datetime
import math

printPort = True

def toggle_printPort():
    global printPort
    printPort = not printPort

keyboard.add_hotkey('esc', toggle_printPort)


secondsDict={}
def draw_time(sd:dict):
    xlabel=[]
    y=[]
    i=10
    for n in sd.keys():
        if len(sd.keys())>60:
            i=math.floor(len(sd.keys())/6)
        convertedTime=datetime.fromtimestamp(n).strftime("%H:%M:%S")
        xlabel.append(convertedTime)
        y.append(sd[n])
        plt.plot(xlabel,y)
        plt.xticks(xlabel[::i], [t for t in xlabel[::i]])    
    plt.show()
    
# Function to process each packet (from either live sniffing or .pcap file)
def process_packet(packet):
    """
    Processes the packet and performs any necessary operations.
    You can extend this function to extract more data or perform actions based on the packet.
    """
    try:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        
        # You can add more logic for TCP, UDP, HTTP, etc.
        if 'TCP' in packet:
            print(f"TCP Packet: Source Port: {packet.tcp.srcport}, Destination Port: {packet.tcp.dstport}")
        
        # Example for HTTP packets
        if 'HTTP' in packet:
            print(f"HTTP Packet: Host: {packet.http.host}")
        
        #curtime=packet.time
        curtime=int(float(packet.frame_info.time_epoch))
        #print(curtime)
        if curtime in secondsDict.keys():
            secondsDict[curtime]+=1
        else:
            secondsDict[curtime]=1
        
    
    except AttributeError as e:
        # Handle cases where packet fields are missing
        print(f"Packet processing error: {e}")

# Function to sniff live traffic and send packets to process_packet function
def sniff_live(interface="WiFi"):
    print(f"Sniffing on interface: {interface}")
    
    # Capture live packets on the specified interface
    capture = pyshark.LiveCapture(interface=interface)

    # Process each packet in the live capture
    for packet in capture.sniff_continuously():  # Adjust or remove packet_count for indefinite sniffing
        if printPort == False:
            print("\nEscape pressed, stopped sniffing...")
            break
        process_packet(packet)  # Send each packet to the processing function

# Function to read packets from a .pcap file and send them to process_packet function
def read_pcap(file):
    print(f"Reading from .pcap file: {file}")
    
    # Read the .pcap file
    cap = pyshark.FileCapture(file)
    
    # Process each packet in the capture
    for packet in cap:
        if printPort == False:
            print("\nEscape pressed, stopped sniffing...")
            break
        process_packet(packet)  # Send each packet to the processing function
    
    # Close the capture when done
    cap.close()

if __name__ == "__main__":
    # You can choose either to sniff traffic live or read from a .pcap file
    choice = input("Choose (1) to sniff live traffic or (2) to read a .pcap file: ")

    if choice == "1":
        interface = input("Enter the network interface (e.g., eth0): ")
        print("Press ESC to stop")
        sniff_live(interface)
    elif choice == "2":
        pcap_file = input("Enter the path to the .pcap file: ")
        print("Press ESC to stop")
        read_pcap(pcap_file)
    else:
        print("Invalid choice. Exiting.")
    with open('json_dmp.json','w') as f:
        #json.dump(secondsDict,f)
        draw_time(secondsDict)
def draw_time(sd:dict):
    x=[]
    y=[]
    for n in sd.keys():
        y.append(n)
        x.append(sd[n])
    gr=plt.plot(x,y)
    plt.show()

