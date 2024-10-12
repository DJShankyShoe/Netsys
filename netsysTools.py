import time
import smtplib
import multiprocessing
from email.mime.text import MIMEText


# Function to send an email
def sendEmail(title="", content="", recipient_email=None, sender_email=None, sender_password=None):

    # Get the email credentials from the configuration file if not provided
    if not sender_email:
        sender_email = retConfig("email_host")
    if not sender_password:
        sender_password = retConfig("email_password")

    # Check if the required parameters are provided
    if recipient_email == None or sender_email == None or sender_password == None:
        return

    # Create a text message
    msg = MIMEText(content)
    msg['Subject'] = title
    msg['From'] = sender_email
    msg['To'] = recipient_email

    # Send the email
    server = smtplib.SMTP('smtp.gmail.com', 587) # Connect to the server
    server.starttls() # Use TLS
    try:
        server.login(sender_email, sender_password) # Login to the email server
        server.sendmail(sender_email, recipient_email, msg.as_string()) # Send the email
    except:
        pass
    server.quit() # Disconnect from the server
    
# Function to run the tool in the background (multiprocessing)
def multiprocesser_executor(tool_class, stdout=[], **kwargs_param):
    # Create a Queue to share data between processes
    queue = multiprocessing.Queue()

    # Pass the multiprocess-queue to the processing class rather than the output stream (communication between processes can't be done normally)
    kwargs_param['stdout'] = queue 
    worker_process = multiprocessing.Process(target=tool_class, kwargs=kwargs_param) # Call processing class here to handle the captured packets
    worker_process.start() # Start the process

    # Loop to get the output from the queue and push it to the output stream
    while True:
        if not queue.empty():
            value = queue.get() # Get the value from the queue
            stdout.append(value) # push the value to output stream for display
            
            # If stop signal is received, break the loop to close the thread
            if value[-1] == "STOP":
                break
        else:
            time.sleep(0.2)  # Sleep to prevent busy-waiting

# Function to read the configuration file
def retConfig(item):
    try:
        with open("data.conf", "r") as file:
            for line in file: # Loop through the file
                if line.startswith(item): # Check if the line starts with the required item
                    data = line.split("=")[1].strip() # Get the data after the '=' sign
                    if data.isnumeric(): # Check if the data is numeric
                        data = int(data)
                    if data:
                        return data
        return None
        
    
    # If the file is not found, create a new one
    except FileNotFoundError:
        with open("data.conf", "w") as file:
            file.write('''
# ---------------------API Key configuration--------------------->
# Get a an api key from https://maclookup.app/, to increase qouta of api calls
# Example: api_key=fgyfbdGTF633g3ebe
api_key=

# ---------------------Email configuration--------------------->
# Set email host and password to send email alerts. These is the email account that will be used to send the alerts. Only allows gmail accounts
# Example: 
# email_host=test@gmail.com
# email_password=testpassword
email_host=
email_password=
email_send_to=

# ---------------------Network Scanner configuration--------------------->
## Set the maximum number of threads to use when scanning the network. The more threads the faster the scan but the more resources it will use
netscan_max_threads=260
## Set the timeout for each scan
netscan_timeout=6
## Number of times to send arp request to each device per scan
netscan_replicate=2

# ---------------------Latency Scanner configuration--------------------->
## Maximum number of times host can be unreachable before ending the scan
latency_unreachableHostMaxCounter=4
## Maximum number of data samples to collect (duration of the test = maxDataSampleSize * 0.5 seconds)
latency_maxDataSampleSize=20''')
            
        retConfig(item) # Call the function again to read the file after creating it