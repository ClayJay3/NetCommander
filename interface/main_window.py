import datetime
import logging
from msilib.schema import Directory
import os
import re
import sys
import webbrowser
import more_itertools as mit
import tkinter as tk
from threading import Thread
from tkinter import messagebox
from tkinter import font
from netmiko.exceptions import ReadTimeout
from interface.popup_window import text_popup
from pyvis.network import Network

from utils.open_connection import ssh_autodetect_info, ssh_telnet

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
        self.switch_tree_checkboxes = []
        self.switch_tree_check_values = []
        self.font = "antiqueolive"
        self.creds_frame = None
        self.username_entrys = []
        self.password_entrys = []
        self.secret_entrys = []
        self.list = None
        self.ip_list = []
        self.discovery_list = []
        self.export_info_list = []
        self.selection_devices_list = []
        self.already_auto_discovering = False
        self.export_permission_error = False
        self.enable_telnet_check = None
        self.change_vlan_check = None
        self.force_telnet_check = None

        # Create UI components.
        self.window = None
        self.command_textbox = None
        self.tree_view_frame = None
        self.tree_canvas = None
        self.closest_hop_entry = None
        self.vlan_old_entry = None
        self.vlan_new_entry = None
        self.vlan_entries_state_enabled = True

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
        self.window.title("NetCommander")
        # Set window to the front of others.
        self.window.attributes("-topmost", True)
        self.window.update()
        self.window.attributes("-topmost", False)
        # Create checkbox variables.
        self.enable_telnet_check = tk.BooleanVar(self.window)
        self.change_vlan_check = tk.BooleanVar(self.window)
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
        device_list_frame.grid(row=1, rowspan=1, columnspan=5, sticky=tk.NSEW)
        device_list_frame.rowconfigure(self.grid_size, weight=1)
        device_list_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for device tree view.
        layer_view_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        layer_view_frame.grid(row=2, rowspan=7, column=0, columnspan=10, sticky=tk.NSEW)
        layer_view_frame.rowconfigure(self.grid_size, weight=1)
        layer_view_frame.columnconfigure(self.grid_size, weight=1)
        # Set grid propogate to allow for grid resizing later.
        # Create frame for entering user login creds.
        self.creds_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        self.creds_frame.grid(row=9, columnspan=5, sticky=tk.NSEW)
        self.creds_frame.rowconfigure(self.grid_size, weight=1)
        self.creds_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for console output
        console_frame = tk.Frame(master=self.window, relief=tk.SUNKEN, borderwidth=15, background="black")
        console_frame.grid(row=1, rowspan=1, column=5, columnspan=5, sticky=tk.NSEW)
        console_frame.rowconfigure(self.grid_size, weight=1)
        console_frame.columnconfigure(self.grid_size, weight=1)
        # Create frame for entering quick command.
        options_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        options_frame.grid(row=9, rowspan=1, column=5, columnspan=5, sticky=tk.NSEW)
        options_frame.rowconfigure(self.grid_size, weight=1)
        options_frame.columnconfigure(self.grid_size, weight=1)
        
        # Populate title frame.
        greeting = tk.Label(master=title_frame, text="Welcome to NetCommander!", font=(self.font, 18))
        greeting.grid()
        author = tk.Label(master=title_frame, text="Created By: Clayton Cowen", underline=True, foreground="blue")
        author.grid()
        font_property = font.Font(author, author.cget("font"))
        font_property.configure(underline=True)
        author.configure(font=font_property)
        author.bind("<Button-1>", lambda event: webbrowser.open("https://www.linkedin.com/in/clayton-cowen/"))

        # Populate loading config frame.
        load_config_title = tk.Label(master=device_list_frame, text="Deploy Setup", height=1, font=(self.font, 20))
        load_config_title.grid(row=0, columnspan=len(self.grid_size), sticky=tk.NW)
        closest_hop_label = tk.Label(master=device_list_frame, text="'Closest hop' switch: ")
        closest_hop_label.grid(row=2, rowspan=1, column=0, columnspan=1, sticky=tk.EW)
        self.closest_hop_entry = tk.Entry(master=device_list_frame, width=10)
        self.closest_hop_entry.grid(row=2, rowspan=1, column=1, columnspan=1, sticky=tk.EW)
        button_deploy = tk.Button(master=device_list_frame, text="DEPLOY", foreground="red", background="white", command=self.deploy_button_callback)
        button_deploy.grid(row=5, rowspan=1, column=0, columnspan=2, sticky=tk.EW)
        button_ping = tk.Button(master=device_list_frame, text="Ping Check", foreground="black", background="white", command=self.mass_ping_button_callback)
        button_ping.grid(row=9, rowspan=1, column=0, sticky=tk.EW)
        button_discover = tk.Button(master=device_list_frame, text="Find Switches", foreground="black", background="white", command=self.auto_discover_switches_callback)
        button_discover.grid(row=9, rowspan=1, column=1, sticky=tk.EW)
        discover_warning = tk.Label(master=device_list_frame, text="Deploy Commands: (Use caution! Incorrect configuration can really suck!)")
        discover_warning.grid(row=0, rowspan=1, column=4, columnspan=6, sticky=tk.W)
        self.command_textbox = tk.Text(master=device_list_frame, width=10, height=5, wrap="none")
        self.command_textbox.grid(row=1, rowspan=8, column=4, columnspan=6, sticky=tk.NSEW)
        scroll_y=tk.Scrollbar(master=device_list_frame, orient='vertical', command=self.command_textbox.yview)    # Add a scrollbar.
        scroll_y.grid(row=1, rowspan=8, column=10, columnspan=1, sticky=tk.NS)
        self.command_textbox['yscrollcommand'] = scroll_y.set
        scroll_x=tk.Scrollbar(master=device_list_frame, orient='horizontal', command=self.command_textbox.xview)    # Add a scrollbar.
        scroll_x.grid(row=9, rowspan=1, column=4, columnspan=6, sticky="new")
        self.command_textbox['xscrollcommand'] = scroll_x.set

        # Populate tree view frame.
        # Create a scrollbar and canvas to store everything in. This is the only way to have a horizontal scrollbar for the whole frame.
        self.tree_canvas = tk.Canvas(master=layer_view_frame, background="lightgrey")
        self.tree_canvas.grid(row=0, rowspan=9, column=0, columnspan=10, sticky=tk.NSEW)
        scrollx=tk.Scrollbar(master=layer_view_frame, orient='horizontal', command=self.tree_canvas.xview)    # Add a scrollbar.
        scrollx.grid(row=10, rowspan=1, column=0, columnspan=10, sticky="ews")
        self.tree_canvas.configure(xscrollcommand=scrollx.set)
        # Create new frame inside of current tree frame for canvas.
        self.tree_view_frame = tk.Frame(master=self.tree_canvas, relief=tk.GROOVE, borderwidth=3, width=100, height=100)
        self.tree_view_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.tree_view_frame.rowconfigure(self.grid_size, weight=1)
        # self.tree_view_frame.columnconfigure(list(range(50)), weight=1)
        # Initialize canvas window.
        self.tree_canvas.create_window((0,0), window=self.tree_view_frame, anchor="nw", tags="frame")
        # Set canvas event to for resizing scrollbar.
        self.tree_canvas.bind("<Configure>",lambda e: self.tree_canvas.config(scrollregion=self.tree_canvas.bbox(tk.ALL)))
        # Update window sizing and member vars.
        self.tree_canvas.update_idletasks()

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
        secret_label = tk.Label(master=options_frame, text="Options:", font=(self.font, 14))
        secret_label.grid(row=0, column=0, columnspan=10, sticky=tk.NSEW)
        enable_vlan_change_checkbox = tk.Checkbutton(master=options_frame, variable=self.change_vlan_check, onvalue=True, offvalue=False)
        enable_vlan_change_checkbox.grid(row=1, rowspan=1, column=0, columnspan=1, sticky=tk.E)
        vlan_change_text = tk.Label(master=options_frame, text="Change VLAN", font=(self.font, 10))
        vlan_change_text.grid(row=1, column=1, columnspan=1, sticky=tk.W)
        self.vlan_old_entry = tk.Entry(master=options_frame, width=10, validate="all", validatecommand=(options_frame.register(lambda input:True if str.isdigit(input) or input == "" else False), "%P"))
        self.vlan_old_entry.grid(row=1, column=2, sticky=tk.W)
        vlan_change_text = tk.Label(master=options_frame, text=" access ports to VLAN", font=(self.font, 10))
        vlan_change_text.grid(row=1, column=3, columnspan=1, sticky=tk.W)
        self.vlan_new_entry = tk.Entry(master=options_frame, width=10, validate="all", validatecommand=(options_frame.register(lambda input:True if (str.isdigit(input) or input == "") else False), "%P"))
        self.vlan_new_entry.grid(row=1, column=4, sticky=tk.W)

        # Populate console frame.
        self.list = tk.Listbox(master=console_frame, background="black", foreground="green", highlightcolor="green")
        self.list.grid(rowspan=10, columnspan=10, sticky=tk.NSEW)

        # Attempt to get data from cache file for username and switch ips.
        try:
            lines = self.cache_file.readlines()
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
                # Clear data lists from discover module.
                clear_discoveries()
                self.switch_tree_checkboxes.clear()
                self.switch_tree_check_values.clear()
                self.selection_devices_list.clear()
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

                # Check if we are able to auth with the first device at least before continuing.
                test_ip = self.closest_hop_entry.get()
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
                    Thread(target=self.auto_discover_back_process, args=([self.closest_hop_entry.get()], usernames, passwords, enable_secrets, self.enable_telnet_check.get(), self.force_telnet_check.get(), True)).start()
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

    def auto_discover_back_process(self, text, usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_data=True) -> None:
        """
        Helper function for auto discover.
        """
        # Discover ips.
        discover_ip_list, export_info = cdp_auto_discover(text, usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_data)

        # Store values in discover list array after clearing it.
        self.discovery_list.clear()
        for addr in discover_ip_list:
            self.discovery_list.append(addr)
        # Store output values in export list after clearing it.
        self.export_info_list.clear()
        for info in export_info:
            self.export_info_list.append(info)

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
                    # Check if the current device is a switch.
                    if device["is_switch"]:
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
                            if device["is_router"]:
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

    def deploy_button_callback(self) -> None:
        """
        This function is triggered everytime the Deploy button is pressed. The process for this button click triggers
        a new thread that send the given commands to all selected devices.

        Parameters:
        -----------
            None
        
        Returns:
        --------
            Nothing
        """
        # Create deploy output directory.
        directory_name = f"deploy_outputs/{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
        os.makedirs(directory_name, exist_ok=True)

        # Loop through each boolean value and match it to the device ip.
        selected_devices = []
        for selected, device in zip(self.switch_tree_check_values, self.selection_devices_list):
            # Get the selected devices status and append them to a list if true.
            if selected.get():
                # Insert object at beginning of list. This effectively reverses the list, so we can just go through is from the beginning when deploying commands.
                selected_devices.insert(0, device)

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

        #  Get commands from textbox.
        text = self.command_textbox.get('1.0', tk.END)

        # Check if selected devices list is empty.
        if len(selected_devices) > 0:
            # Check to make sure the user entered something for the vlan change if selected.
            if self.change_vlan_check.get() and len(self.vlan_old_entry.get()) <= 0 and len(self.vlan_new_entry.get()) <= 0:
                # Print log and show messagebox.
                self.logger.warning("Can't start deploy because no vlans have been entered to change! If you don't want to enter vlans, then uncheck the box in the options pane.")
                messagebox.showwarning(message="Can't start deploy because the user didn't specify old and new vlans even though the checkbox was ticked.")
            else:
                # Before starting threads, ask user if they are sure they want to continue.
                self.logger.info("Asking user if they are sure they want to start the deploy process...")
                user_result = messagebox.askyesno(title="ATTENTION!", message="Are you sure you want to start the deploy process? This will make changes to the devices!")
                # Check user choice.
                if user_result:
                    # Print log.
                    self.logger.info("Command deploy has been started!")
                    # Start a new thread that connects to each ip and runs the given commands.
                    # Thread(target=self.deploy_button_back_process, args=(text, usernames, passwords, enable_secrets, self.enable_telnet_check.get(), self.force_telnet_check.get())).start()
                    bad_deploys = self.deploy_button_back_process(text, selected_devices, usernames, passwords, enable_secrets, self.enable_telnet_check.get(), self.force_telnet_check.get(), directory_name)

                    # Print log and show messagebox stating the deploy has finished.
                    self.logger.info(f"The command deploy has finished! {len(bad_deploys)} out of {len(selected_devices)} did not successfully execute the given commands. Opening window with the IPs now...")
                    messagebox.showinfo(message=f"The command deploy has finished! {len(bad_deploys)} out of {len(selected_devices)} did not successfully execute the given commands.")
                    # Check if we need to open the window.
                    if len(bad_deploys) > 0:
                        text_popup(title="Bad Deploy Devices", text=[f"{device['ip_addr']} - {device['hostname']}\n" for device in bad_deploys])
                else:
                    # Print log.
                    self.logger.info("Command deploy has been canceled.")
        else:
            # Print log and show messagebox.
            self.logger.warning("Can't start deploy because no devices have been selected.")
            messagebox.showwarning(message="Can't start deploy because no devices have been selected.")

    def deploy_button_back_process(self, command_text, devices, usernames, passwords, enable_secrets, enable_telnet, force_telnet, directory_name="deploy_outputs/") -> None:
        """
        Helper function for Deploy Button, runs in a new thread.
        """
        # Create instance variables.
        bad_deploys = []

        # Set window size. Take it out of fullscreen.
        self.window.wm_state('iconic')

        # Print log.
        self.logger.info(f"NetCommander will be running these commands on the selected switches: \n{command_text}")

        # Loop through all selected devices.
        for device in devices:
            # Attempt to login to the first device.
            ssh_device = ssh_autodetect_info(usernames, passwords, enable_secrets, enable_telnet, force_telnet, device["ip_addr"])
            connection = ssh_telnet(ssh_device, enable_telnet, force_telnet, store_config_info=True)
            
            # Check if device connection was successful.
            if connection is not None and connection.is_alive():
                # Check the privilege level of our connection. Must be 15 to execute all commands.
                if "15" in connection.send_command("show privilege"):
                    # Check if commands are empty.
                    if len(command_text) > 1:
                        # Print log.
                        self.logger.info(f"Connected to device {device['ip_addr']}. Running commands...")

                        output = ""
                        # Run the commands on the switch and show output, then ask the user if the output looks good.
                        for line in command_text.splitlines():
                            # Catch timeouts.
                            try:
                                # Send the current command to the switch.
                                output += f"\n{connection.find_prompt()}{line}\n"
                                output += connection.send_command(line, expect_string="#")
                            except ReadTimeout:
                                self.logger.warning(f"Couldn't get command output for {device['ip_addr']}. It is likely the commands still ran.")
                                messagebox.showwarning(message=f"Couldn't get command output for {device['ip_addr']}. However, it is likely the commands still ran and the console just took too long to print output.")

                        # Check if the user have enabled vlan changing.
                        if self.change_vlan_check.get():
                            # Get vlan new and old numbers from the user.
                            old_vlan = self.vlan_old_entry.get()
                            new_vlan = self.vlan_new_entry.get()

                            # Loop through interfaces and get a list of interfaces with interfaces on VLAN1.
                            interface_vlan_change_list = []
                            for interface in ssh_device["interfaces"]:
                                # Catch key errors for malformed interface output.
                                try:
                                    # Check the interface vlan.
                                    if int(interface["switchport access vlan"]) == int(old_vlan) and interface["vlan_status"] == old_vlan and not interface["switchport mode trunk"] and ("Fa" not in interface["name"] and "Ap" not in interface["name"]) and "trunk" not in interface["vlan_status"]:
                                        interface_vlan_change_list.append(interface["name"])
                                except KeyError as error:
                                    self.logger.error(f"KeyError ({error}): An interface output for {device['hostname']} was not received properly, skipping...")

                            # Check that we have at least 1 interface to change.
                            vlan_command_text = ""
                            if len(interface_vlan_change_list) > 0:
                                # Append interfaces changed to output
                                output += f"\n\n{interface_vlan_change_list}"

                                # Convert the list into more compact ranges, CiscoIOS can only handle 5-8 ranges.
                                interface_port_types = {}
                                for interface in interface_vlan_change_list:
                                    # Cutoff first two or three letters of interface and add key to dictionary if it doesn't exist. If it doesn exist, then append it to the list in the dictionary.
                                    key = re.split("/", interface[::-1], 1)[-1][::-1]
                                    if key not in interface_port_types.keys():
                                        interface_port_types[key] = [re.split("/|Po", interface)[-1]]
                                    else:
                                        interface_port_types[key].append(re.split("/|Po", interface)[-1])

                                # Group the interfaces together to be more efficient.
                                vlan_command_text = "end\nconf t\n"
                                interface_ranges = ""
                                range_counter = 0
                                for key in interface_port_types.keys():
                                    # Get the interface list.
                                    interface_numbers = interface_port_types[key]
                                    interface_numbers = list(map(int, interface_numbers))
                                    # Group numbers.
                                    interface_numbers = list(self.find_ranges(interface_numbers))
                                    # Parse command text.
                                    for range in interface_numbers:
                                        # Check if we have hit five ranges.
                                        if range_counter >= 5:
                                            # Remove last comma and space from interface range text.
                                            interface_ranges = interface_ranges[:-2]
                                            # Build commands list for vlan change.
                                            vlan_command_text += f"int range {interface_ranges}\n"
                                            vlan_command_text += f"sw acc vlan {new_vlan}\n"
                                            # Clear interface_range text and reset counter.
                                            interface_ranges = ""
                                            range_counter = 0

                                        # Lookout for port channel interfaces.
                                        if "Po" in key:
                                            interface_ranges += f"{key}, "
                                        # Check if the current range is a tuple or a single integer.
                                        elif isinstance(range, tuple):
                                            interface_ranges += f"{key}/{range[0]}-{range[1]}, "
                                        else:
                                            interface_ranges += f"{key}/{range}, "
                                        
                                        # Increment counter.
                                        range_counter += 1
                                
                                # Remove last comma and space from interface range text.
                                interface_ranges = interface_ranges[:-2]
                                # Build commands list for vlan change.
                                vlan_command_text += f"int range {interface_ranges}\n"
                                vlan_command_text += f"sw acc vlan {new_vlan}\n"
                                # Add end to exit global config mode.
                                vlan_command_text += "end\n"

                            # Run the commands on the switch and show output, then ask the user if the output looks good.
                            output += "\n\n"
                            for line in vlan_command_text.splitlines():
                                # Catch timeouts.
                                try:
                                    # Send the current command to the switch.
                                    output += f"\n{connection.find_prompt()}{line}\n"
                                    output += connection.send_command(line, expect_string="#")
                                except ReadTimeout:
                                    self.logger.warning(f"Couldn't get command output for {device['ip_addr']}. It is likely the commands still ran.")
                                    messagebox.showwarning(message=f"Couldn't get command output for {device['ip_addr']}. However, it is likely the commands still ran and the console just took too long to print output.")

                        # Show the output to the user and ask if it is correct.
                        text_popup(f"Command Output for {device['hostname']}, {device['ip_addr']}", output, x_grid_size=10, y_grid_size=10)
                        # Write output to a file.
                        with open(f"{directory_name}/{device['hostname']}({device['ip_addr']}).txt", 'w+') as file:
                            for line in output:
                                file.write(line)
                        # Ask the user if the output is correct.
                        correct_output = messagebox.askyesno(title=f"Confirm correct output for {device['hostname']}, {device['ip_addr']}", message="Is this output correct? Its output will be saved to the deploy_outputs folder.")
                        # Ask the user if they want to continue.
                        continue_deploy = messagebox.askyesno(title="Continue deploy?", message="Would you like to continue the command deploy?")
                        # correct_output = True
                        # continue_deploy = True

                        # If the output was incorrect add the switch to a list.
                        if not correct_output:
                            bad_deploys.append(device)
                        # If the user doesn't want to continue the deploy then stop looping.
                        if not continue_deploy:
                            # Print log.
                            self.logger.info("The deploy has been canceled by the user.")
                            # Disconnection from the current device.
                            connection.disconnect()
                            # Exit for loop.
                            break
                    else:
                        # Print log and show messagebox to user.
                        self.logger.info("Command textbox is empty!")
                        messagebox.showwarning(message="Command textbox is empty!")
                        # Store all device in the bad deploy list.
                        bad_deploys = devices
                        # Disconnection from the current device.
                        connection.disconnect()
                        # Exit for loop.
                        break
                else:
                    # Print log and show messagebox.
                    self.logger.error(f"Insignificant privilege level to safely run all commands on {device['ip_addr']}. Skipping and adding to bad deploy list...")
                    messagebox.showerror(message=f"Insignificant privilege level to safely run all commands on {device['ip_addr']}. The device will be skipped and marked as a bad deploy.")
                    # Append current device to bad deploy list.
                    bad_deploys.append(device)

                # Disconnection from device.
                connection.disconnect()
            else:
                # Print log and show messagebox.
                self.logger.error(f"Failed to connection to {device['ip_addr']}")
                messagebox.showerror(message=f"Couldn't connect to {device['ip_addr']}. Moving on to next device.")
                # Append current device to bad deploy list.
                bad_deploys.append(device)

            # Update main window.
            self.window.update()

        # Print bad deploy devices to logs.
        self.logger.info(f"Unable to fully deploy commands to these devices: {bad_deploys}")

        return bad_deploys

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
        # Create instance variables.
        text = []

        # Print status to console.
        self.logger.info("\n---------------------------------------------------------\nPinging all devices now...\n---------------------------------------------------------")

        # Check if scan has been ran.
        if len(self.switch_tree_check_values) > 0 and any([value.get() for value in self.switch_tree_check_values]):
            # Loop through each boolean value and match it to the device ip.
            for selected, device in zip(self.switch_tree_check_values, self.selection_devices_list):
                if selected.get():
                    text.append(device["ip_addr"])
        else:
            # Get text from textbox.
            text = [self.closest_hop_entry.get()]

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

        # Update options entries and checkboxes.
        if not self.change_vlan_check.get() and self.vlan_entries_state_enabled:
            # Disable elements.
            self.vlan_old_entry.configure(state="disable")
            self.vlan_new_entry.configure(state="disable")
            # Update toggle var.
            self.vlan_entries_state_enabled = False
        elif self.change_vlan_check.get() and not self.vlan_entries_state_enabled:
            # Disable elements.
            self.vlan_old_entry.configure(state="normal")
            self.vlan_new_entry.configure(state="normal")
            # Update toggle var.
            self.vlan_entries_state_enabled = True

        # Update the textbox with the discovering list if it's not empty and not being updated.
        if len(self.discovery_list) > 0 and not self.already_auto_discovering:
            # Delete the current contents of the frame.
            for widget in self.tree_view_frame.winfo_children():
                # Remove widget.
                widget.destroy()

            # Check if an error occured.
            if self.export_permission_error:
                # Show messagebox.
                messagebox.showerror(title="ERROR", message="Unable to export CSV file. Please make sure the old CSV file is closed if you opened it in a text editor or Excel.")
                # Set toggle.
                self.export_permission_error = False
            else:
                # Clear old checkbox list.
                self.switch_tree_check_values.clear()
                self.switch_tree_checkboxes.clear()
                # Get the max recursion. number from the device list.
                recursion_layers = max([info["recursion_level"] for info in self.export_info_list]) + 2
                # Populate the tree view window with a textbox per layer containing checkboxes representing the devices on that layer.
                approx_column_span = 3
                # Reconfig column numbers to match recursion levels.
                self.tree_view_frame.columnconfigure(list(range(recursion_layers * approx_column_span)), weight=1)
                # Get and store the closest hop entry.
                closest_hop_switch = self.closest_hop_entry.get()
                for i in range(recursion_layers):
                    # Check if we are at index -1.
                    if i == 0:
                        # Get the device that matches the given closest hop entry ip address.
                        layer_devices = [device for device in self.export_info_list if device["ip_addr"] == closest_hop_switch]
                    else:
                        # Get all devices on current recursion layer.
                        layer_devices = [device for device in self.export_info_list if device["recursion_level"] == (i - 1) and device["ip_addr"] != closest_hop_switch]

                    # Check if any device in the recursion layer is a switch, at least one must be true to add new column.
                    if any([device["is_switch"] for device in layer_devices]):
                        # Create new textbox and label.
                        text_box_label = tk.Label(master=self.tree_view_frame, text=f"'Hop' Distance {i}")
                        text_box_label.grid(row=0, rowspan=1, column=(i * approx_column_span), columnspan=approx_column_span, sticky=tk.SW)
                        text_box = tk.Text(master=self.tree_view_frame, width=10, height=5)
                        text_box.grid(row=1, rowspan=9, column=(i * approx_column_span), columnspan=approx_column_span, sticky=tk.NSEW)

                    # Populate textbox with checkboxes.
                    for device in layer_devices:
                        # Check if device is a switch.
                        if device["is_switch"]:
                            # Create checkbox and boolean var.
                            check_value = tk.BooleanVar(text_box)
                            checkbox = tk.Checkbutton(master=text_box, text=f"{device['hostname']} ({device['ip_addr']})", variable=check_value, onvalue=True, offvalue=False)
                            # Append to list.
                            self.switch_tree_check_values.append(check_value)
                            self.switch_tree_checkboxes.append(checkbox)
                            self.selection_devices_list.append(device)
                            # Add to textbox.
                            text_box.window_create("1.0", window=checkbox)
                            text_box.insert("end", "    \n")

                    # Check if any device in the recursion layer is a switch, at least one must be true to add scrollbar over textbox.
                    if any([device["is_switch"] for device in layer_devices]):
                        # Add scrollbar to textbox.
                        scrolly=tk.Scrollbar(master=self.tree_view_frame, orient='vertical', command=text_box.yview)    # Add a scrollbar.
                        scrolly.grid(row=1, rowspan=9, column=(i * approx_column_span) + (approx_column_span - 1), columnspan=1, sticky="nse")
                        text_box['yscrollcommand'] = scrolly.set
                        scrollx=tk.Scrollbar(master=self.tree_view_frame, orient='horizontal', command=text_box.xview)    # Add a scrollbar.
                        scrollx.grid(row=9, rowspan=1, column=(i * approx_column_span), columnspan=approx_column_span, sticky="ews")
                        text_box['xscrollcommand'] = scrollx.set

                # Set the frame switch to match the canvas and requested size, this makes it scroll past the max grid size.
                self.tree_canvas.itemconfig('frame', width=recursion_layers * 325)
                self.tree_canvas.config(scrollregion=self.tree_canvas.bbox(tk.ALL))
                
                # Open exported html in a new webbrowser.
                webbrowser.open('file://' + os.path.realpath("exports/hierarchical_graph.html"))

                # Show messagebox stating discovery is complete.
                messagebox.showinfo(title="Discovery Finished", message="Discovery is finished. All discovered IPs have been put in the IP textbox. If exports were enabled, they have been saved to the local directory of this app.")

            # Clear list just to be sure.
            self.discovery_list.clear()

        # Update the tree frame canvas and canvas frame sizes.
        self.tree_canvas.itemconfig('frame', height=self.tree_canvas.winfo_height())
        self.tree_canvas.update_idletasks()

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
        
        # Clear file and move back to start marker.
        self.cache_file.truncate(0)
        self.cache_file.seek(0)
        # Store contents of username in cache file.
        cache_data = []
        for user_entry in self.username_entrys:
            # Get value.
            username = user_entry.get()
            # Make sure value isn't empty.
            if len(username) > 0:
                # Append value.
                cache_data.append(username)
        # Store contents of switch list in cache file.
        for line in cache_data:
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

    def find_ranges(self, iterable):
        """
        Turns [1,2,3,4,5,6,10] into [(1,6), 10]. This function uses the 'yield' keyword to be
        memory efficient and because it returns an iterable object.

        Parameters:
        -----------
            iterable - An iterable object

        Returns:
        --------
            list - A list of integers and tuples that represent the compressed version of the input.
        """
        for group in mit.consecutive_groups(iterable):
            group = list(group)
            if len(group) == 1:
                yield group[0]
            else:
                yield group[0], group[-1]
