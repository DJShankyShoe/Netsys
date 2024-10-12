import tkinter as tk
import datetime as dt
from collections import deque

class Logger:
    def __init__(self, root):
        self.stdoutValues = deque() # stores log to be added
        self.idMapper = {} # dict of all currently open windows
        self.root = root # root window of the GUI
        self.update_log() # start the update log function


    # Return the output stream to make it available to other classes
    def get_output_stream(self):
        return self.stdoutValues


    # Insert output mesage to GUI 
    def update_log(self):
        if self.stdoutValues:
            id, stdout = self.stdoutValues.popleft()

            # check if the window is already created else create a new window
            if id not in self.idMapper:
                self.create_window(id)
            
            # add timestamp
            timeNow=str(dt.datetime.now().strftime("%H:%M:%S"))+": "
            self.idMapper[id]['outputList'].insert(tk.END,timeNow+stdout)          
            self.idMapper[id]['outputList'].see("end") # Scroll to the end of the listbox

            # check if the window need to be closed
            if stdout == "STOP":
                self.on_closing_window(id)

        self.root.after(100, self.update_log)  # Check every 100 ms


    # Create an output window to display messages
    def create_window(self, id):
        # create a new log window
        window = tk.Toplevel(self.root)
        window.geometry("350x300")
        window.config(bg="grey18", cursor="circle")
        window.title(id)
        outputList=tk.Listbox(window) # create a listbox that holds the output

        # assign a scrollbar to the listbox
        scrollbar=tk.Scrollbar(window,command=outputList.yview).pack(side=tk.RIGHT,fill=tk.Y)
        outputList.pack(side=tk.TOP,fill=tk.BOTH,expand=tk.TRUE)
        outputList.configure(yscrollcommand=scrollbar,bg="grey18",fg="white")

        # pass both the toplevel of the window and the listbox that contains the output
        self.idMapper[id] ={'window':window ,'outputList':outputList}
        window.protocol("WM_DELETE_WINDOW", lambda: self.on_closing_window(id)) # Bind the close event to the close handler


    # Close the window and remove it from the idMapper
    def on_closing_window(self, id):
        self.idMapper[id]['window'].destroy()  # Close the window
        del self.idMapper[id] # Remove the window from the idMapper

