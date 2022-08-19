from cgi import test
from cgitb import enable
import logging
import os
import sys
import webbrowser
import tkinter as tk
from threading import Thread
from tkinter import messagebox
from tkinter import font

from pyvis.network import Network

from interface.popup_window import MultipleCheckboxPopup
from utils.open_connection import ssh_autodetect_info

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.net_crawl import cdp_auto_discover, clear_discoveries
from utils.ping import ping_of_death


# Create MainUI class.
class MainUI():
    """
    Class that serves as a the frontend for all of the programs user interactable functions.
    """
    def __init__(self) -> None:
        # Create class variables and objects.
        self.logger = logging.getLogger(__name__)
        self.window_is_open = True
        self.grid_size = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.export_options_list = ["ROUTER", "SWITCH", "WIRELESS AP", "IP PHONE", "CAMERA"]
        self.export_option_items = []
        self.export_options_check_values = []
        self.font = "antiqueolive"
        self.window = None
        self.creds_frame = None
        self.text_box  = None
        self.username_entrys = []
        self.password_entrys = []
        self.secret_entrys = []
        self.list = None
        self.ip_list = []
        self.discovery_list = []
        self.already_auto_discovering = False
        self.export_permission_error = False
        self.enable_telnet_check = None
        self.force_telnet_check = None

        # Open log file for displaying in console window.
        self.log_file = open("logs/latest.log", "r", encoding="utf-8")
        # Create cache file.
        if not os.path.exists("cache.cache"):
            self.cache_file = open("cache.cache", "w+")
        else:
            self.cache_file = open("cache.cache", "r+")

        # Set loggging level of netmiko and paramiko.
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        logging.getLogger("netmiko").setLevel(logging.ERROR)

    def initialize_window(self) -> None:
        """
        Creates and populates all MainUI windows and components.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        self.logger.info("Initializing main window...")

        # Create new tk window.
        self.window = tk.Tk()
        # Set window closing actions.
        self.window.protocol("WM_DELETE_WINDOW", self.close_window)
        # Set window title.
        self.window.title("Mostly Universal Switch Configurator")
        # Set window to the front of others.
        self.window.attributes("-topmost", True)
        self.window.update()
        self.window.attributes("-topmost", False)
        # Create checkbox variables.
        self.enable_telnet_check = tk.BooleanVar(self.window)
        self.force_telnet_check = tk.BooleanVar(self.window)

        # Setup window grid layout.
        self.window.rowconfigure(self.grid_size, weight=1, minsize=50)
        self.window.columnconfigure(self.grid_size, weight=1, minsize=75)

        #######################################################################
        #               Create window components.
        #######################################################################
        # Create frame for title block.
        title_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        title_frame.grid(row=0, columnspan=10, sticky=tk.NSEW)
        title_frame.columnconfigure(0, weight=1)
        # Create frame for loading and config switch section.
        device_list_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        device_list_frame.grid(row=1, rowspan=8, columnspan=5, sticky=tk.NSEW)
        device_list_frame.rowconfigure(self.grid_size, weight=1)
        device_list_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for entering user login creds.
        self.creds_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        self.creds_frame.grid(row=9, columnspan=5, sticky=tk.NSEW)
        self.creds_frame.rowconfigure(self.grid_size, weight=1)
        self.creds_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for entering quick command.
        options_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        options_frame.grid(row=1, rowspan=2, column=5, columnspan=5, sticky=tk.NSEW)
        options_frame.rowconfigure(self.grid_size, weight=1)
        options_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for console output
        console_frame = tk.Frame(master=self.window, relief=tk.SUNKEN, borderwidth=15, background="black")
        console_frame.grid(row=3, rowspan=7, column=5, columnspan=5, sticky=tk.NSEW)
        console_frame.rowconfigure(self.grid_size, weight=1)
        console_frame.columnconfigure(self.grid_size, weight=1)
        
        # Populate title frame.
        greeting = tk.Label(master=title_frame, text="Welcome to NetCrawler", font=(self.font, 18))
        greeting.grid()
        author = tk.Label(master=title_frame, text="Created By: Clayton Cowen", underline=True, foreground="blue")
        author.grid()
        font_property = font.Font(author, author.cget("font"))
        font_property.configure(underline=True)
        author.configure(font=font_property)
        author.bind("<Button-1>", lambda event: webbrowser.open("https://www.linkedin.com/in/clayton-cowen/"))

        # Populate loading config frame.
        load_config_title = tk.Label(master=device_list_frame, text="Discovery Devices", height=1, font=(self.font, 20))
        load_config_title.grid(row=0, columnspan=len(self.grid_size), sticky=tk.N)
        discover_warning = tk.Label(master=device_list_frame, text="(When autodiscovering only enter one IP from each subnet!)")
        discover_warning.grid(row=0, rowspan=1, column=0, columnspan=1, sticky=tk.SW)
        self.text_box = tk.Text(master=device_list_frame, width=10, height=5)
        self.text_box.grid(row=1, rowspan=9, columnspan=9, sticky=tk.NSEW)
        button = tk.Button(master=device_list_frame, text="Map Network", foreground="black", background="white", command=self.auto_discover_switches_callback)
        button.grid(row=1, rowspan=4, column=9, sticky=tk.NSEW)
        button_ping = tk.Button(master=device_list_frame, text="Ping Check", foreground="black", background="white", command=self.mass_ping_button_callback)
        button_ping.grid(row=6, rowspan=4, column=9, sticky=tk.NSEW)

        # Populate login creds frame.
        creds_title = tk.Label(master=self.creds_frame, text="Login Credentials", font=(self.font, 18))
        creds_title.grid(row=0, column=0, columnspan=6, sticky=tk.W)
        enable_telnet_checkbox = tk.Checkbutton(master=self.creds_frame, text="Enable Telnet", variable=self.enable_telnet_check, onvalue=True, offvalue=False)
        enable_telnet_checkbox.grid(row=1, rowspan=1, column=8, columnspan=1, sticky=tk.E)
        force_telnet_checkbox = tk.Checkbutton(master=self.creds_frame, text="Force Telnet", variable=self.force_telnet_check, onvalue=True, offvalue=False)
        force_telnet_checkbox.grid(row=1, rowspan=1, column=9, columnspan=1, sticky=tk.E)
        creds_title = tk.Label(master=self.creds_frame, text="(Enable secret is not required if enable mode is default for vty connections.)")
        creds_title.grid(row=0, column=6, columnspan=4, sticky=tk.E)
        add_cred_button = tk.Button(master=self.creds_frame, text="Add Creds", foreground="black", background="white", command=self.add_creds_callback)
        add_cred_button.grid(row=5, column=0, sticky=tk.NSEW)
        username_label = tk.Label(master=self.creds_frame, text="Username:")
        username_label.grid(row=5, column=4, sticky=tk.NSEW)
        username_entry = tk.Entry(master=self.creds_frame, width=10)
        username_entry.grid(row=5, column=5, sticky=tk.NSEW)
        self.username_entrys.append(username_entry)     # Append username field to list.
        password_label = tk.Label(master=self.creds_frame, text="Password:")
        password_label.grid(row=5, column=6, sticky=tk.NSEW)
        password_entry = tk.Entry(master=self.creds_frame, show="*", width=10)
        password_entry.grid(row=5, column=7, sticky=tk.NSEW)
        self.password_entrys.append(password_entry)     # Append password field to list.
        secret_label = tk.Label(master=self.creds_frame, text="Enable Secret:")
        secret_label.grid(row=5, column=8, sticky=tk.NSEW)
        new_secret_entry = tk.Entry(master=self.creds_frame, show="*", width=10)
        new_secret_entry.grid(row=5, column=9, sticky=tk.NSEW)
        self.secret_entrys.append(new_secret_entry)

        # Populate option frame.
        secret_label = tk.Label(master=options_frame, text="Graphing Export Options:", font=(self.font, 14))
        secret_label.grid(row=0, column=0, columnspan=10, sticky=tk.NSEW)
        row_counter = 1
        column_counter = 0
        for item in self.export_options_list:
            # Create and store new boolean var to hold checkbox value.
            check_value = tk.BooleanVar(self.window)
            # Set default values to True.
            check_value.set(True)
            self.export_options_check_values.append(check_value)
            # Create and place new checkbox.
            checkbox = tk.Checkbutton(master=options_frame, text=item, variable=check_value, onvalue=True, offvalue=False)
            checkbox.grid(row=row_counter, rowspan=1, column=column_counter, sticky=tk.W)
            # Update counter.
            column_counter += 1
            # Check if we are at the end column of the frame.
            if column_counter >= len(self.grid_size):
                row_counter += 1
                column_counter = 0
            # Store value.
            self.export_option_items.append(checkbox)

        # Populate console frame.
        self.list = tk.Listbox(master=console_frame, background="black", foreground="green", highlightcolor="green")
        self.list.grid(rowspan=10, columnspan=10, sticky=tk.NSEW)

        # Attempt to get data from cache file for username and switch ips.
        try:
            lines = self.cache_file.readlines()
            # Check length of file.
            if len(lines) >= 2:
                # Get total number of ips.
                total_ips = int(lines.pop(0))
                # Loop through and append each ip to textbox.
                for i in range(total_ips):
                    self.text_box.insert(tk.END, lines.pop(0))
                
                # Check length of cache again for username.
                while len(lines) > 0:
                    # Use the first entry box initially.
                    if len(self.username_entrys[0].get()) > 0:
                        # Create and place new entry boxes.
                        username_label = tk.Label(master=self.creds_frame, text="Username:")
                        username_label.grid(row=len(self.username_entrys) + 5, column=4, sticky=tk.NSEW)
                        new_username_entry = tk.Entry(master=self.creds_frame, width=10)
                        new_username_entry.grid(row=len(self.username_entrys) + 5, column=5, sticky=tk.NSEW)
                        password_label = tk.Label(master=self.creds_frame, text="Password:")
                        password_label.grid(row=len(self.username_entrys) + 5, column=6, sticky=tk.NSEW)
                        new_password_entry = tk.Entry(master=self.creds_frame, show="*", width=10)
                        new_password_entry.grid(row=len(self.username_entrys) + 5, column=7, sticky=tk.NSEW)
                        secret_label = tk.Label(master=self.creds_frame, text="Enable Secret:")
                        secret_label.grid(row=len(self.username_entrys) + 5, column=8, sticky=tk.NSEW)
                        new_secret_entry = tk.Entry(master=self.creds_frame, show="*", width=10)
                        new_secret_entry.grid(row=len(self.username_entrys) + 5, column=9, sticky=tk.NSEW)

                        # Fill new entry box.
                        new_username_entry.insert(0, lines.pop(0).strip())

                        # Append entry boxes to list.
                        self.username_entrys.append(new_username_entry)
                        self.password_entrys.append(new_password_entry)
                        self.secret_entrys.append(new_secret_entry)
                    else:
                        # Fill new entry box.
                        username_entry.insert(0, lines.pop(0).strip())
        except Exception:
            self.logger.error("Unable to read cache file. It must be corrupted.")

    def add_creds_callback(self) -> None:
        """
        This function is triggered everytime the Add Creds button is pressed. It adds new username and password boxes.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Check if we have created more than 5 different users.
        if len(self.username_entrys) < 5:
            # Create and place new entry boxes.
            username_label = tk.Label(master=self.creds_frame, text="Username:")
            username_label.grid(row=len(self.username_entrys) + 5, column=4, sticky=tk.NSEW)
            new_username_entry = tk.Entry(master=self.creds_frame, width=10)
            new_username_entry.grid(row=len(self.username_entrys) + 5, column=5, sticky=tk.NSEW)
            password_label = tk.Label(master=self.creds_frame, text="Password:")
            password_label.grid(row=len(self.username_entrys) + 5, column=6, sticky=tk.NSEW)
            new_password_entry = tk.Entry(master=self.creds_frame, show="*", width=10)
            new_password_entry.grid(row=len(self.username_entrys) + 5, column=7, sticky=tk.NSEW)
            secret_label = tk.Label(master=self.creds_frame, text="Enable Secret:")
            secret_label.grid(row=len(self.username_entrys) + 5, column=8, sticky=tk.NSEW)
            new_secret_entry = tk.Entry(master=self.creds_frame, show="*", width=10)
            new_secret_entry.grid(row=len(self.username_entrys) + 5, column=9, sticky=tk.NSEW)

            # Append entry boxes to list.
            self.username_entrys.append(new_username_entry)
            self.password_entrys.append(new_password_entry)
            self.secret_entrys.append(new_secret_entry)

            # Print log.
            self.logger.info(f"Added credential box {len(self.username_entrys)}")
        else:
            # Print log.
            self.logger.warning("No more credential boxes are allowed, too many can be inefficient. Consider configuring your switches for a RADIUS/TACACS+ server.")
            # Show messagebox.
            messagebox.showwarning(title="Warning", message="No more credential boxes are allowed, too many can be inefficient. Consider configuring your switches for a RADIUS/TACACS+ server.")

    def auto_discover_switches_callback(self) -> None:
        """
        This function is triggered everytime the Auto Discover Fast button is pressed. It spawns a new process
        that uses recursion to find the next switch connected to the current one and so on.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Check if a password has been entered.
        if any(len(entry.get()) > 0 for entry in self.password_entrys):
            # Check if auto discover has already been started.
            if not self.already_auto_discovering:
                # Open the popup and get the return values.
                export_data_selections = []
                # Loop through the current selections and store their value in the user submit array.
                for check_val in self.export_options_check_values:
                    # Get var boolean and store.
                    export_data_selections.append(check_val.get())
                # Clear data lists from discover module.
                clear_discoveries()
                # Get username and password lists.
                usernames = [username.get() for username in self.username_entrys]
                passwords = [password.get() for password in self.password_entrys]
                enable_secrets = [secret.get() for secret in self.secret_entrys]
                # Remove empty passwords.
                for i, password in enumerate(passwords):
                    # Check length.
                    if len(password) <= 0:
                        # Remove list item.
                        usernames.pop(i)
                        passwords.pop(i)
                        enable_secrets.pop(i)
                # Get text from textbox.
                text = self.text_box.get('1.0', tk.END).splitlines()
                if len(text) > 25:
                    # Show warning if textbox has more than 25 entries.
                    messagebox.showwarning(title="WARNING!", message="Discovering from too many devices at the same time may cause slow ssh/telnet console output which can result in parsing errors.")

                # Check if we are able to auth with the first device at least before continuing.
                test_ip = text[0].strip()
                auth_success = False
                # Get secret
                # Attempt to auth.
                first_switch = ssh_autodetect_info(usernames, passwords, enable_secrets, self.enable_telnet_check.get(), self.force_telnet_check.get(), test_ip)
                # Check if auth was successful.
                if first_switch["host"] != "Unable_to_Authenticate":
                    # Set toggle.
                    auth_success = True
                
                # Only continue if the first switch login was successful.
                if auth_success:
                    # Start backprocess for auto discover.
                    Thread(target=self.auto_discover_back_process, args=(text, usernames, passwords, enable_secrets, self.enable_telnet_check.get(), self.force_telnet_check.get(), True, export_data_selections)).start()
                    # Set safety toggle.
                    self.already_auto_discovering = True
                    # Print log.
                    self.logger.info("Auto discover has been triggered.")
                    messagebox.showinfo(message="Auto discovery has been started, please be patient while the program searches for new devices.\nOnly run autodiscovery occasionally or when multiple new devices are connected to the network.")
                else:
                    # Print log.
                    self.logger.info("Unable to authenticate with the first device. Make sure at least one set of creds is compatible.")
                    messagebox.showerror(message="Unable to authenticate with the first device. Make sure at least one set of creds is compatible.")
            else:
                # Print log.
                self.logger.warning("User tried to start auto discover while it was already running.")
                messagebox.showwarning(message="Auto discover is already running, please be patient. Watch the console output for discover info.")
        else:
            # Print log and show messagebox.
            self.logger.warning("You must enter username and password credentials. Otherwise, I can't log into the switch!")
            messagebox.showwarning(title="Warning", message="You must enter username and password credentials.")

    def auto_discover_back_process(self, text, usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_data=True, export_data_selections=[]) -> None:
        """
        Helper function for auto discover.
        """
        # Discover ips.
        discover_ip_list, export_info = cdp_auto_discover(text, usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_data)

        # Store values in discover list array.
        for addr in discover_ip_list:
            self.discovery_list.append(addr)

        # If export_data is toggled on, then write the result data to a CSV file.
        if export_data and len(export_info) > 0:
            # Create output directory.
            os.makedirs("exports", exist_ok=True)

            # Make sure file isn't already open.
            try:
                # Write normal discovery info.
                with open('exports/network_crawl.csv', 'w') as file:
                    # Write the first label line.
                    file.write(str(list(export_info[0].keys())).replace("license_info", "")[1:-1])
                    # Loop through each device and append info.
                    data_string = "\n"
                    for device in export_info:
                        # Build info string.
                        for key in list(export_info[0].keys()):
                            # Don't append license info.
                            if key != "license_info":
                                data_string += str(device[key]) + ", "
                        
                        # Add newline.
                        data_string += "\n"

                    # Write the final string.
                    file.write(data_string)

                # Write license info.
                data_string = ""
                with open('exports/license_info.txt', 'w') as file:
                    # Loop through each device and append info.
                    for device in export_info:
                        # Check if device is a switch.
                        if device["is_switch"]:
                            # Save hostname, ip, and license_info.
                            data_string += f"{device['hostname']} ({device['ip_addr']}):\n\n"
                            data_string += device["license_info"]
                            # Add newline.
                            data_string += "\n\n#######################################################################################\n\n"

                    # Write the final string.
                    file.write(data_string)

                # Open network discovery map.
                # Create new network map object from pyvis.
                graph_net = Network(width="1920px", height="1080px", bgcolor='#222222', font_color='white', notebook=True, directed=False)
                # Turn off color inheritance.
                graph_net.inherit_edge_colors(status=False)
                # Generate a list of node weights depending on how many times their names show up in the export list.
                # Also generate a list of colors depending on device type.
                name_weights = []
                colors = []
                filtered_export_info = []
                for device in export_info:
                    # Check if the matching data list isn't empty.
                    if export_data_selections is not None and len(export_data_selections) > 0:
                        # Create list of booleans for device type.
                        type_boolean_list = [device["is_router"], device["is_switch"], device["is_wireless_ap"], device["is_phone"], device["is_camera"]]
                        # Get a list of matching values for corresponding positions in the list.
                        matching = False
                        for i, bool_val in enumerate(export_data_selections):
                            # Check if both are true.
                            if bool_val and type_boolean_list[i]:
                                matching = True
                    else:
                        # Just export everything is the user didn't choose.
                        matching = True

                    # If the device is valid per user input, then append to new list and do other stuff.
                    if matching:
                        # Remove license info from dictionary.
                        device.pop("license_info", None)
                        # Append device to new list.
                        filtered_export_info.append(device)

                        # Get the device hostname.
                        hostname = device["hostname"]
                        weight = 0
                        # Loop through export info again and count occurances.
                        for info in export_info:
                            # Check if the hostname or parent hostname equals the current hostname.
                            if info["hostname"] == hostname or info["parent_host"] == hostname:
                                # Add one to weight.
                                weight += 1
                        # Append weight to weights list.
                        name_weights.append(weight)

                        # Check device type and append color.
                        if device["is_wireless_ap"]:
                            # Orange.
                            colors.append("#eb6200")
                        elif device["is_switch"]:       # is_switch and is_router can both be true, router overides.
                            if device["is_router"] and export_data_selections[0]:
                                # Green.
                                colors.append("#21ad11")
                            else:
                                # Blue
                                colors.append("#3300eb")
                        elif device["is_phone"]:
                            # Yellow
                            colors.append("#f0e805")
                        elif device["is_camera"]:
                            # Purple.
                            colors.append("#9f3dae")

                # Create a lamba function to generate random hex color codes.
                # gen_rand_hex = lambda: random.randint(0,255)
                # Add the nodes to the network graph.
                # graph_net.add_nodes(list(range(len(filtered_export_info))),
                #                 value=name_weights,
                #                 title=[str(info) for info in filtered_export_info],
                #                 label=[info["hostname"] for info in filtered_export_info],
                #                 color=["#%02X%02X%02X" % (gen_rand_hex(), gen_rand_hex(), gen_rand_hex()) for i in range(len(filtered_export_info))])
                # Add the nodes to the network diagram.
                graph_net.add_nodes(list(range(len(filtered_export_info))),
                            value=name_weights,
                            title=[str(str(info)[1:-1].replace(",", "\n")) for info in filtered_export_info],
                            label=[info["hostname"] for info in filtered_export_info],
                            color=colors)

                # Add the edges/paths to the nodes. This is super ineffficient.
                for i, device in enumerate(filtered_export_info):
                    # Get current device hostname. Cutoff domain. Also grab local interface.
                    hostname = device["hostname"].split(".", 1)[0]
                    local_interface = device["local_trunk_interface"]
                    # Get current device parent hostname and interface.
                    parent_hostname = device["parent_host"]
                    parent_interface = device["parent_trunk_interface"]
                    for j, device2 in enumerate(filtered_export_info):
                        # Get search device hostname. Cutoff domain.
                        search_hostname = device2["hostname"].split(".", 1)[0]
                        # Check if parent and search name are the same.
                        if parent_hostname == search_hostname:
                            # Only add labels if at least one of them isn't NULL.
                            if local_interface != "NULL" or parent_interface != "NULL":
                                # Add edges based on node names.
                                graph_net.add_edge(j, i, arrows="to", color=graph_net.get_node(i)["color"], title=parent_interface + " -> " + local_interface)
                            else:
                                # Add edges based on node names.
                                graph_net.add_edge(j, i, arrows="to", color=graph_net.get_node(i)["color"])

                # Turn on settings panel.
                graph_net.show_buttons()
                # Export normal graph.
                graph_net.show("exports/universe_graph.html")
                # Set new graph options.
                graph_net.set_options('''
                const options = {
                        "configure": {
                        "enabled": true
                    },
                    "nodes": {
                        "font": {
                        "size": 5
                        }
                    },
                    "layout": {
                        "hierarchical": {
                        "enabled": true,
                        "blockShifting": false,
                        "edgeMinimization": false,
                        "parentCentralization": false
                        }
                    },
                    "physics": {
                        "hierarchicalRepulsion": {
                        "centralGravity": 0,
                        "nodeDistance": 195,
                        "avoidOverlap": 1
                        },
                        "minVelocity": 0.75,
                        "solver": "hierarchicalRepulsion"
                    }
                }''')
                # Export new graph.
                graph_net.show("exports/hierarchical_graph.html")
            except PermissionError as error:
                # Catch permissions error if file is already opened by user from a previous session.
                self.logger.error("Unable to export CSV file. Please make sure the old CSV file is closed if you opened it in a text editor or Excel.", exc_info=error)
                self.export_permission_error = True

        # Print log.
        self.logger.info(f"FINISHED! Discovered a total of {len(self.discovery_list)} IPs: {self.discovery_list}")

        # Reset safety toggle.
        self.already_auto_discovering = False

    def mass_ping_button_callback(self) -> None:
        """
        This function is triggered everytime the Mass Ping button is pressed. The process for this button click triggers
        a ping check to all given devices.

        Parameters:
        -----------
            None
        
        Returns:
        --------
            Nothing
        """
        # Print status to console.
        self.logger.info("\n---------------------------------------------------------\nPinging all devices now...\n---------------------------------------------------------")

        # Get text from textbox.
        text = self.text_box.get('1.0', tk.END).splitlines()
        # Ping each switch listed in the textbox to get a list containing their status.
        Thread(target=ping_of_death, args=(text, self.ip_list,)).start()

    def update_window(self) -> None:
        """
        Update the windows UI components and values.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        # Update the console window with the log text.
        where = self.log_file.tell()
        line = self.log_file.readline()
        if not line:
            self.log_file.seek(where)
        else:
            self.list.insert(0, line)

        # Update the textbox with the discovering list if it's not empty and not being updated.
        if len(self.discovery_list) > 0 and not self.already_auto_discovering:
            # Delete current contents of textbox.
            self.text_box.delete("1.0", tk.END)
            # Loop through and append each ip to textbox.
            for i in range(len(self.discovery_list)):
                self.text_box.insert(tk.END, self.discovery_list.pop(0) + "\n")

            # Check if an error occured.
            if self.export_permission_error:
                # Show messagebox.
                messagebox.showerror(title="ERROR", message="Unable to export CSV file. Please make sure the old CSV file is closed if you opened it in a text editor or Excel.")
                # Set toggle.
                self.export_permission_error = False
            else:
                # Show messagebox stating discovery is complete.
                messagebox.showinfo(title="Discovery Finished", message="Discovery is finished. All discovered IPs have been put in the IP textbox. If exports were enabled, they have been saved to the local directory of this app.")

            # Clear list just to be sure.
            self.discovery_list.clear()

        # Call main window event loop.
        self.window.update()

    def close_window(self) -> None:
        """
        This method is called when the main window closes.
        """
        # Print info.
        self.logger.info("Main window exit action has been invoked. Performing closing actions.")

        # Set bool value.
        self.window_is_open = False
        
        # Get contents of text box and username entry.
        switch_ips = self.text_box.get('1.0', tk.END).splitlines()
        switch_ips = list(filter(None, switch_ips))
        # Clear file and move back to start marker.
        self.cache_file.truncate(0)
        self.cache_file.seek(0)
        # Store contents of username in cache file.
        switch_ips.insert(0, str(len(switch_ips)))
        for user_entry in self.username_entrys:
            # Get value.
            username = user_entry.get()
            # Make sure value isn't empty.
            if len(username) > 0:
                # Append value.
                switch_ips.append(username)
        # Store contents of switch list in cache file.
        for line in switch_ips:
            # Only write if line isn't empty.
            if len(line) > 0:
                self.cache_file.write(line + "\n")

        # Close files.
        self.log_file.close()
        self.cache_file.close()

        # Close window.
        self.window.destroy()

    def get_is_window_open(self) -> bool:
        """
        Returns if the window is still open and running.

        Parameters:
        -----------
            None

        Returns:
        --------
            Nothing
        """
        return self.window_is_open
