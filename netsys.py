# Libraries
import psutil
import logger as lg
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from multiprocessing import freeze_support

from concurrent.futures import ThreadPoolExecutor

# Local file imports
import netsysTools
import trafficParser as tp
import latencyTester as lt
import portMapper as pm
import trafficAnalyzer as ta
import identifyNetEnum as enum
import networkScanner as ns

class GraphicalInterfaceApp:
    def __init__(self, root, stdout):
        self.root = root # Initialize the root window
        self.root.title("NetSys") # Set the title of the window 
        self.root.geometry("450x350") # Set the window size
        self.root.config(bg="grey18", cursor="circle")  # Mouse cursor
        self.font = "Times New Roman" # Set the font style
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) # Bind the close event to the close handler
        self.futures = []  # List to track submitted thread tasks
        
        self.stdout = stdout # Initialize the stdout variable
        self.executor = ThreadPoolExecutor() 

        self.create_tools_page() # main page
        self.create_traffic_page()
        self.create_latency_page()
        self.create_networkScanner_page()



# -----------------------------------------------------------------Tool Page-----------------------------------------------------------------
    # Show tool page
    def show_tool_page(self):
        self.tool_page.pack(fill="both", expand=True)
        self.latency_page.pack_forget()
        self.traffic_page.pack_forget()
        self.networkScanner_page.pack_forget()
        
    # Create tool page
    def create_tools_page(self):
        # tool page
        self.tool_page = tk.Frame(self.root, bg="grey18")
        self.tool_page.pack(fill="both", expand=True)
        self.class_type = None # Set the class type to None as default

        # Title
        label = tk.Label(self.tool_page, text="Tools", font=(self.font, 14))
        label.pack(pady=20) # Padding on the y-axis
        label.configure(bg="grey18", fg="white") # Background and foreground color

        # Button to traffic metric
        self.tool_btn_traffic = tk.Button(self.tool_page, text="Traffic Metric", font=(self.font, 12), command=lambda: self.show_traffic_page(ta.TrafficAnalyzer), width=15, height=1, fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.tool_btn_traffic.pack(pady=10)

        # Button to port analysis
        self.tool_btn_port_analysis = tk.Button(self.tool_page, text="Port Analysis", font=(self.font, 12), command=lambda: self.show_traffic_page(pm.PortMapper), width=15, height=1, fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.tool_btn_port_analysis.pack(pady=10)

        # Button to latency dropdown
        self.tool_btn_latency = tk.Button(self.tool_page, text="Latency Test", font=(self.font, 12), command=lambda: self.show_latency_page(lt.LatencyTester), width=15, height=1, fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.tool_btn_latency.pack(pady=10)

        # Button to network scanner 
        self.tool_btn_network_scanner = tk.Button(self.tool_page, text="Network Scanner", font=(self.font, 12), command=lambda: self.show_networkScanner_page(ns.NetworkScanner), width=15, height=1, fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.tool_btn_network_scanner.pack(pady=10)
        
        # Button to identify enumeration
        self.tool_btn_identify_enum = tk.Button(self.tool_page, text="Identify Enumeration", font=(self.font, 12), command=lambda: self.show_traffic_page(enum.IdentifyNetEnum) , width=15, height=1, fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.tool_btn_identify_enum.pack(pady=10)

        # Button Hover
        self.bind_hover_events([self.tool_btn_traffic, self.tool_btn_port_analysis, self.tool_btn_latency, self.tool_btn_network_scanner, self.tool_btn_identify_enum])



# -----------------------------------------------------------------Traffic Page-----------------------------------------------------------------
    # Show traffic page
    def show_traffic_page(self, class_type):
        self.class_type = class_type
        self.traffic_page.pack(fill="both", expand=True)
        self.tool_page.pack_forget()
    
    # Create traffic page
    def create_traffic_page(self):

        # Set the position of the labels and buttons
        self.traffic_column1, self.traffic_column2, self.traffic_column3 = 70, 160, 360
        self.traffic_row1, self.traffic_row2, self.traffic_row3 = 75, 105, 135

        # Main
        self.traffic_page = tk.Frame(self.root, bg="grey18")

        # Traffic Selection title
        traffic_label = tk.Label(self.traffic_page, text="Traffic Selection", font=(self.font, 14))
        traffic_label.pack(pady=20) # Padding on the y-axis
        traffic_label.configure(bg="grey18", fg="white") # Background and foreground color

        # Traffic label display
        self.traffic_label = tk.Label(self.traffic_page, text="Traffic Type: ", font=(self.font, 10), bg="grey18", fg="white")
        self.traffic_label.place(x=self.traffic_column1 ,y=self.traffic_row1)

        # Traffic Type dropdown menu
        cur = 0
        data = ["PCAP File", "Sniff Live Traffic"] 
        self.traffic_sniff_combo = ttk.Combobox(self.traffic_page,state="readonly",values=data, width=27, justify='center')
        self.traffic_sniff_combo.place(x=self.traffic_column2 ,y=self.traffic_row1+2)
        self.traffic_sniff_combo.bind("<<ComboboxSelected>>", self.network_type_option_change)
        self.traffic_sniff_combo.current(cur)
        self.capture_type = "pcap" # Default capture type

        # Import File
        self.traffic_btn_import = tk.Button(self.traffic_page, text="Import File", command=lambda: self.import_file(), font=(self.font, 9))
        self.traffic_btn_import.place(x=self.traffic_column3 ,y=self.traffic_row1)
        # self.traffic_btn_import.place_forget() # Hide initially
        self.file_path = None # Set deafult file_path as empty

        # Create a label to display the file name
        self.traffic_filename_label = tk.Label(self.traffic_page, text="", font=(self.font, 10), bg="grey18", fg="white")

        # Interface Label display
        self.traffic_interface_label = tk.Label(self.traffic_page, text="Interface Type: ", font=(self.font, 10), bg="grey18", fg="white")

        # Interface dropdown list
        cur = 0
        data = list(psutil.net_if_addrs().keys()) # Set interface values as user's 
        self.traffic_interface_combo = ttk.Combobox(self.traffic_page, state="readonly", values = data, width=27, justify='center')
        self.traffic_interface_combo.bind("<<ComboboxSelected>>", self.traffic_interface_option_change)
        self.traffic_interface_combo.current(cur)
        self.interface_type = data[0] # Set interface values to default

        # Run PCAP File
        self.traffic_btn_run_file = tk.Button(self.traffic_page, text="Run PCAP File", font=(self.font, 10), command=lambda: self.execute_data(self.traffic_btn_run_file), fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.traffic_btn_run_file.place_forget()  # Hide initially
        
        # Run Button
        self.pcapFile = None # Set default pcapFile as empty
        self.traffic_btn_interface = tk.Button(self.traffic_page, text="Run", font=(self.font, 10), command=lambda: self.execute_data(self.traffic_btn_interface), fg="black", bg="light grey", activebackground="DeepSkyBlue")
        self.traffic_btn_interface.place_forget()  # Hide initially

        # Back Button
        self.traffic_btn_back = tk.Button(self.traffic_page, text="Back", font=(self.font, 10), command=self.reset_traffic_page, bg="light grey", fg="black", activebackground="DeepSkyBlue")
        self.traffic_btn_back.place(x=30, y=290)

        # Button Hover
        self.bind_hover_events([self.traffic_btn_import, self.traffic_btn_back, self.traffic_btn_run_file, self.traffic_btn_interface])

    # Function to reset the traffic page
    def reset_traffic_page(self):
    #Resets all widgets on the traffic page to their default states.
    
        # Reset the traffic type combobox to its default value
        self.traffic_sniff_combo.current(0)  # Reset to first option "PCAP File"
        
        # Reset the file path and filename label
        self.file_path = None
        self.traffic_filename_label.config(text="")  # Clear the file name display

        # Reset the interface dropdown (if it's visible)
        self.traffic_interface_combo.current(0)  # Reset to the first interface

        # Hide any elements that were shown after selection
        self.traffic_btn_run_file.place_forget()
        self.traffic_btn_interface.place_forget()
        self.traffic_interface_combo.place_forget()
        self.traffic_interface_label.place_forget() 
        self.traffic_btn_import.place(x=self.traffic_column3 ,y=self.traffic_row1)
        # Navigate back to the previous page
        self.show_tool_page()

    # Import PCAP File 
    def import_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PCAPNG files", "*.pcap *.pcapng")])
        if self.file_path:
            file_name = self.file_path.split("/")[-1]  # Get the file name from the path
            self.traffic_filename_label.config(text=f"Selected File:     {file_name}")  # Display file name
            self.traffic_filename_label.place(x=self.traffic_column1, y=self.traffic_row2) # Show the File Label 
            self.traffic_btn_run_file.place(x=self.traffic_column2, y=self.traffic_row3)  # Show the Run File button
    
    # Traffic Page Traffic Type dropdown menu
    def network_type_option_change(self, event):
        sniff_selected_value = self.traffic_sniff_combo.get()
        if sniff_selected_value == "PCAP File":
            self.traffic_interface_combo.place_forget()
            self.traffic_btn_import.place(x=self.traffic_column3 ,y=self.traffic_row1)
            self.traffic_btn_interface.place_forget()
            self.traffic_interface_label.place_forget() 
            self.capture_type = "pcap"
            
        elif sniff_selected_value == "Sniff Live Traffic":
            self.traffic_btn_import.place_forget()
            self.traffic_interface_label.place(x=self.traffic_column1 ,y=self.traffic_row2)
            self.traffic_interface_combo.place(x=self.traffic_column2 ,y=self.traffic_row2)
            self.traffic_btn_run_file.place_forget()
            self.traffic_filename_label.place_forget()
            self.traffic_btn_interface.place(x=self.traffic_column2 ,y=self.traffic_row3)
            self.capture_type = "live"

    # Traffic Page Interface Type creation - when sniff live traffic is selected
    def traffic_interface_option_change(self, event):
        self.interface_type = self.traffic_interface_combo.get() # Get the selected interface value



# -----------------------------------------------------------------Latency Page-----------------------------------------------------------------
    # Show latency dropdown page
    def show_latency_page(self, class_type):
        self.class_type = class_type
        self.latency_page.pack(fill="both", expand=True)
        self.tool_page.pack_forget()

    # Create latency page
    def create_latency_page(self):
        # latency dropdown Page
        self.latency_page = tk.Frame(self.root, bg="grey18")
        
        # Title
        latency_label = tk.Label(self.latency_page, text="Latency Tester", font=(self.font, 14))
        latency_label.pack(pady=20) # Padding on the y-axis
        latency_label.configure(bg="grey18", fg="white") # Background and foreground color

        # Select Option title
        latency_label = tk.Label(self.latency_page, text="Select Option:  ", font=(self.font, 11))
        latency_label.configure(bg="grey18", fg="white")
        latency_label.place (x=70 ,y=75)

        # Combobox Selection
        cur = 0
        data = ["Custom"] + lt.LatencyTester().get_hosts()
        self.latency_combo = ttk.Combobox(self.latency_page,state="readonly",values=data, width=20)
        self.latency_combo.place(x=170 ,y=77)
        self.latency_combo.bind("<<ComboboxSelected>>", self.latency_hostname_option_change)
        self.latency_combo.current(cur) # Set default to "Custom"
        self.latency_hostname = data[cur] # Create variable to store latency hostname

        # Label name for hostname and hostport
        self.latency_label_hostname = tk.Label(self.latency_page, text="Hostname:  ", font=(self.font, 11))
        self.latency_label_hostname.configure(bg="grey18", fg="white")
        self.latency_label_hostname.place_forget()

        self.latency_label_hostport = tk.Label(self.latency_page, text="Port:  ", font=(self.font, 11))
        self.latency_label_hostport.configure(bg="grey18", fg="white")
        self.latency_label_hostport.place_forget()

        # hostname text widget
        self.latency_hostname_widget = tk.Entry(self.latency_page, width=16)

        # hostport text widget
        self.latency_hostport = 80 # Create variable to store latency hostport (default 80)
        self.latency_hostport_widget = tk.Entry(self.latency_page, width=5)
        self.latency_hostport_widget.insert(0, self.latency_hostport)


        # Run Button
        self.latency_btn_run = tk.Button(self.latency_page, text="Run", font=(self.font, 10), command=lambda: self.execute_data(self.latency_btn_run), bg="light grey", fg="black", activebackground="DeepSkyBlue")
        self.latency_btn_run.place_forget()

        # Back Button
        self.latency_btn_back = tk.Button(self.latency_page, text="Back", font=(self.font, 10), command=self.reset_latency_page, bg="light grey", fg="black", activebackground="DeepSkyBlue")
        self.latency_btn_back.place(x=30, y=290)

        # Button Hover
        self.bind_hover_events([self.latency_btn_run, self.latency_btn_back])

        # Show custom text widget initially
        self.latency_hostname_option_change(None)

    # Function to reset the latency page
    def reset_latency_page(self):
    #Resets all widgets on the latency page to their default states.
        # Reset the latency combo box to its default value (Custom)
        self.latency_combo.current(0)
        
        # Reset hostname and hostport fields to default and hide them
        self.latency_hostname_widget.delete(0, tk.END)  # Clear any entered hostname
        self.latency_hostport_widget.delete(0, tk.END)  # Clear any entered port
        self.latency_hostport_widget.insert(0, 80)  # Reset port to 80 (default)
        
        # Show hostname and hostport fields
        self.latency_label_hostport.place(x=125 ,y=138)   #show the port label
        self.latency_hostport_widget.place(x=170 ,y=138) # Show the port text widget
        self.latency_label_hostname.place(x=90 ,y=108) # show the label name
        self.latency_hostname_widget.place(x=170 ,y=108) # Show the text widget
        

        # Show the run button
        self.latency_btn_run.place(x=330, y=138)
        
        # Navigate back to the main tool page
        self.show_tool_page()
    
    # Get the text from the Text widget
    def latency_text_change(self, event, value):
        if value == "hostname":
            self.latency_hostname = self.latency_hostname_widget.get()
        elif value == "hostport":
            self.latency_hostport = self.latency_hostport_widget.get()
    
    # Latency Page "Custom" dropdown menu
    def latency_hostname_option_change(self, event):
        #Callback function to show/hide the Text widget based on the selected option.
        self.latency_hostname = self.latency_combo.get()
        if self.latency_hostname == "Custom" or event == None:
            self.latency_label_hostname.place(x=90 ,y=108) # show the label name
            self.latency_hostname_widget.place(x=170 ,y=108) # Show the text widget
            self.latency_hostname_widget.bind("<KeyRelease>", lambda event: self.latency_text_change(event, "hostname")) # Bind the text widget to the <<Modified>> event

            self.latency_label_hostport.place(x=125 ,y=138)   #show the port label
            self.latency_hostport_widget.place(x=170 ,y=138) # Show the port text widget

            self.latency_btn_run.place(x=330, y=138)
            self.latency_hostport_widget.bind("<KeyRelease>", lambda event: self.latency_text_change(event, "hostport")) # Bind the text widget to the <<Modified>> event

        else:
            # Hide the Text widget and Label
            self.latency_hostname_widget.place_forget()
            self.latency_label_hostname.place_forget()
            self.latency_hostport_widget.place_forget()
            self.latency_label_hostport.place_forget()

            # Show run button
            self.latency_btn_run.place(x=330, y=75)



# -----------------------------------------------------------------Network Scanner Page-----------------------------------------------------------------
    # Show networkScanner page
    def show_networkScanner_page(self, class_type):
        self.class_type = class_type
        self.networkScanner_page.pack(fill="both", expand=True)
        self.tool_page.pack_forget()

    # Create networkScanner page
    def create_networkScanner_page(self):
        self.networkScanner_page = tk.Frame(self.root, bg="grey18")

        neworkScanner_label = tk.Label(self.networkScanner_page, text="Network Scanner", font=(self.font, 14))
        neworkScanner_label.pack(pady=20) # Padding on the y-axis
        neworkScanner_label.configure(bg="grey18", fg="white") # Background and foreground color
        
        # NeworkScanner Interface Label display
        self.neworkScanner_interface_label = tk.Label(self.networkScanner_page, text="Interface Type: ", font=(self.font, 10), bg="grey18", fg="white")
        self.neworkScanner_interface_label.place(x=70 ,y=75)

        # Interface dropdown menu
        cur = 0
        data = list(psutil.net_if_addrs().keys()) # Set interface values as user's
        self.neworkScanner_interface_combo = ttk.Combobox(self.networkScanner_page, state="readonly", values = data, width=25, justify='center')
        self.neworkScanner_interface_combo.bind("<<ComboboxSelected>>", self.networkScanner_option_change)
        self.neworkScanner_interface_combo.current(cur)
        self.neworkScanner_interface_combo.place(x=170 ,y=77)
        self.interface_type = data[cur]

        # NeworkScanner speed Label display
        self.neworkScanner_speed_label = tk.Label(self.networkScanner_page, text="Scan Speed: ", font=(self.font, 10), bg="grey18", fg="white")
        self.neworkScanner_speed_label.place(x=70 ,y=115)

        # Speed dropdown menu
        cur = 2
        data = ns.NetworkScanner().getScanSpeed()
        self.neworkScanner_speed_combo = ttk.Combobox(self.networkScanner_page, state="readonly", values = data, width=25, justify='center')
        self.neworkScanner_speed_combo.bind("<<ComboboxSelected>>", self.networkScanner_option_change)
        self.neworkScanner_speed_combo.current(cur)
        self.neworkScanner_speed_combo.place (x=170 ,y=115)
        self.neworkScanner_speed = data[cur]
        
        # Embedded warning text
        warning = "Warning: By using this feature, you confirm that you are authorized to scan the network. Unauthorized use may be illegal, and you are responsible for your actions"
        embedded_text = tk.Label(self.networkScanner_page, text=warning, font=(self.font, 10), bg="grey18", fg="lightgrey", wraplength=400, justify="center")
        embedded_text.place (x=50, y=160)

        # Back Button
        self.traffic_btn_back = tk.Button(self.networkScanner_page, text="Back", font=(self.font, 10), command=self.reset_networkScanner_page, bg="light grey", fg="black", activebackground="DeepSkyBlue")
        self.traffic_btn_back.place(x=30, y=290)

        # Run Button
        self.traffic_btn_run = tk.Button(self.networkScanner_page, text="Run", font=(self.font, 10), command=lambda: self.execute_data(self.traffic_btn_run), bg="light grey", fg="black", activebackground="DeepSkyBlue", width=10)
        self.traffic_btn_run.place(x=200, y=220)

        # Button Hover
        self.bind_hover_events([self.traffic_btn_run, self.traffic_btn_back])

    # NetworkScanner Page Interface Type dropdown menu
    def networkScanner_option_change(self, event):
        self.interface_type = self.neworkScanner_interface_combo.get()
        self.neworkScanner_speed = self.neworkScanner_speed_combo.get()

    # Function to reset the network scanner page
    def reset_networkScanner_page(self):
    # Resets the network scanner page to its default state.
        # Reset the interface combo box to its default value
        self.neworkScanner_interface_combo.current(0)
        
        # Reset the scan speed combo box to its default value
        self.neworkScanner_speed_combo.current(2)  # Assuming 2 is the default position

        # Navigate back to the tool page
        self.show_tool_page()



# -----------------------------------------------------------------Functionality-----------------------------------------------------------------
    # Function to handle and execute user parsed data
    def execute_data(self, button):
        # Multiprocess flag is set to True to create a new process for the PortMapper beacause it is unable start if started by a thread
        if self.class_type == pm.PortMapper:
            self.multirun(button, tp.TrafficParser, netType=self.capture_type, pcapFile=self.file_path, interface=self.interface_type, multiprocess=True, stdout=self.stdout, packetProcessor=pm.PortMapper, passInterface=True)

        # Multiprocess flag is set to True to create a new process for the TrafficAnalyzer beacause it is unable start if started by a thread
        elif self.class_type == ta.TrafficAnalyzer:
            self.multirun(button, tp.TrafficParser, netType=self.capture_type, pcapFile=self.file_path, interface=self.interface_type, multiprocess=True, stdout=self.stdout, packetProcessor=ta.TrafficAnalyzer)
        
        elif self.class_type == lt.LatencyTester:
            self.multirun(button, lt.LatencyTester, host=self.latency_hostname, port=self.latency_hostport, main_multiprocess=True, stdout=self.stdout)
        
        elif self.class_type == ns.NetworkScanner:
            self.multirun(button, ns.NetworkScanner, root=self.root, interface=self.interface_type, speed=self.neworkScanner_speed, stdout=self.stdout)

        elif self.class_type == enum.IdentifyNetEnum:
            self.multirun(button, tp.TrafficParser, root=self.root, netType=self.capture_type, pcapFile=self.file_path, interface=self.interface_type, stdout=self.stdout, packetProcessor=enum.IdentifyNetEnum)

    # Bind hover events to buttons
    def bind_hover_events(self, buttons):
        for btn in buttons:
            btn.bind("<Enter>", self.on_enter)
            btn.bind("<Leave>", self.on_leave)

    # Change button color on hover
    def on_enter(self, event):
        event.widget.config(bg='lightblue')

    # Reset button color on leave
    def on_leave(self, event):
        event.widget.config(bg='lightgrey')
    
    # Function to close the window
    def on_closing(self):
        # Check if there are any active threads
        if any(not future.done() for future in self.futures):
            messagebox.showerror("Error", "Close other Netsys windows first") # Show an error message
        else:
            self.executor.shutdown(wait=True)  # Wait for all threads to finish before closing the window
            self.root.destroy()

    # Function to run the tool in the background (multithreading)
    def multirun(self, button, tool_class, main_multiprocess=False, **kwargs_param):
        button.config(state=tk.DISABLED) # Disable the button to prevent multiple clicks

        # Check if the tool is to be run in a separate process or thread
        if main_multiprocess:
            future = self.executor.submit(netsysTools.multiprocesser_executor, tool_class, **kwargs_param) # Submit the task to run in the background
        else:
            future = self.executor.submit(tool_class, **kwargs_param) # Submit the task to run in the background

        self.futures.append(future) # Append the future object to the list
        future.add_done_callback(lambda f: self.task_complete(button))   # Callback to handle completion
    
    # Function to re-enable the button after the task completes
    def task_complete(self, button):
        button.config(state=tk.NORMAL) # Re-enable the button after the task completes
        


# Initialize and run the app
if __name__ == "__main__":
    freeze_support() # for pyinstaller on Windows
    root = tk.Tk()
    logging = lg.Logger(root)  # Initialize the Logger
    stdout = logging.get_output_stream()  # Access the deque
    GraphicalInterfaceApp(root, stdout)
    root.mainloop()
