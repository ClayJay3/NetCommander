import datetime
import logging
from msilib.schema import Directory
import os
import re
import sys
import webbrowser
import tkinter as tk
from threading import Thread
from tkinter import messagebox
from tkinter import font
from netmiko.exceptions import ReadTimeout
from interface.popup_window import text_popup
from utils.deploy_options import change_port_vlans, setup_dhcp_snooping_on_trunks, setup_dynamic_arp_inspection_on_trunks
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

        # Deploy vars.
        self.already_deploying = False
        self.directory_name = ""
        self.selected_devices = []
        self.usernames = []
        self.passwords = []
        self.enable_secrets = []
        self.command_text = ""
        self.user_result = False
        self.bad_deploys = []
        self.deploy_devices_total_count = 0
        self.deploy_frames_state_enabled = True
        self.exit_messages = {}
        self.switch_output = []
        self.deploy_thread = None
        self.deploy_device = None

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

        # Create UI component variables.
        self.window = None
        self.command_textbox = None
        self.tree_view_frame = None
        self.tree_canvas = None
        self.closest_hop_entry = None
        self.enable_telnet_check = None
        self.change_vlan_check = None
        self.toggle_voice_vlan_check = None
        self.force_telnet_check = None
        self.vlan_old_entry = None
        self.vlan_new_entry = None
        self.access_vlan_radio_select = None
        self.voice_vlan_radio_select = None
        self.vlan_entries_state_enabled = True
        self.dhcp_snoop_vlan_entry = None
        self.disable_dhcp_snooping_option82_checkbox = None
        self.dhcp_snoop_vlan_entry_state_enabled = True
        self.arp_inspection_vlan_entry = None
        self.enable_arp_inspection_checkbox = None
        self.arp_inspection_vlan_entry_state_enabled = True
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
        self.toggle_voice_vlan_check = tk.BooleanVar(self.window)
        self.turbo_deploy_check = tk.BooleanVar(self.window)
        self.force_telnet_check = tk.BooleanVar(self.window)
        self.dhcp_snooping_check = tk.BooleanVar(self.window)
        self.dhcp_snooping_option82_check = tk.BooleanVar(self.window, True)
        self.arp_inspection_check = tk.BooleanVar(self.window)

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
        self.options_frame = tk.Frame(master=self.window, relief=tk.GROOVE, borderwidth=3)
        self.options_frame.grid(row=9, rowspan=1, column=5, columnspan=5, sticky=tk.NSEW)
        self.options_frame.rowconfigure(self.grid_size, weight=1)
        self.options_frame.columnconfigure(self.grid_size, weight=1)
        
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

        #########################################################################################################
        # Populate option frame.
        #########################################################################################################
        options_label = tk.Label(master=self.options_frame, text="Options:", font=(self.font, 14))
        options_label.grid(row=0, column=0, columnspan=10, sticky=tk.NSEW)
        #########################################################################################################
        vlan_options_frame = tk.Frame(master=self.options_frame, relief=tk.GROOVE, borderwidth=2)   # Create frame from grouping vlan options.
        vlan_options_frame.grid(row=1, rowspan=2, column=0, columnspan=5, sticky=tk.NSEW)
        vlan_options_frame.rowconfigure(self.grid_size, weight=1)
        vlan_options_frame.columnconfigure(self.grid_size, weight=1)
        enable_vlan_change_checkbox = tk.Checkbutton(master=vlan_options_frame, variable=self.change_vlan_check, onvalue=True, offvalue=False)
        enable_vlan_change_checkbox.grid(row=0, rowspan=1, column=0, columnspan=1, sticky=tk.E)
        vlan_change_text = tk.Label(master=vlan_options_frame, text="Change VLAN", font=(self.font, 10))
        vlan_change_text.grid(row=0, column=1, columnspan=1, sticky=tk.W)
        self.vlan_old_entry = tk.Entry(master=vlan_options_frame, width=10, validate="all", validatecommand=(vlan_options_frame.register(lambda input:True if str.isdigit(input) or input == "" else False), "%P"))
        self.vlan_old_entry.grid(row=0, column=2, sticky=tk.W)
        vlan_change_text = tk.Label(master=vlan_options_frame, text=" ports to VLAN", font=(self.font, 10))
        vlan_change_text.grid(row=0, column=3, columnspan=1, sticky=tk.W)
        self.vlan_new_entry = tk.Entry(master=vlan_options_frame, width=10, validate="all", validatecommand=(vlan_options_frame.register(lambda input:True if (str.isdigit(input) or input == "") else False), "%P"))
        self.vlan_new_entry.grid(row=0, column=4, sticky=tk.W)
        self.access_vlan_radio_select = tk.Radiobutton(master=vlan_options_frame, text="Change access VLANs", variable=self.toggle_voice_vlan_check, value=False)
        self.access_vlan_radio_select.grid(row=1, column=0, columnspan=10, sticky=tk.W)
        self.voice_vlan_radio_select = tk.Radiobutton(master=vlan_options_frame, text="Change voice VLANs", variable=self.toggle_voice_vlan_check, value=True)
        self.voice_vlan_radio_select.grid(row=1, column=3, columnspan=6, sticky=tk.W)
        #########################################################################################################
        turbo_options_frame = tk.Frame(master=self.options_frame, relief=tk.GROOVE, borderwidth=2)   # Create frame from grouping turbo options.
        turbo_options_frame.grid(row=3, rowspan=2, column=0, columnspan=5, sticky=tk.NSEW)
        turbo_options_frame.rowconfigure(self.grid_size, weight=1)
        turbo_options_frame.columnconfigure(self.grid_size, weight=1)
        enable_turbo_deploy_checkbox = tk.Checkbutton(master=turbo_options_frame, variable=self.turbo_deploy_check, onvalue=True, offvalue=False)
        enable_turbo_deploy_checkbox.grid(row=0, rowspan=1, column=0, columnspan=1, sticky=tk.E)
        turbo_deploy_text = tk.Label(master=turbo_options_frame, text="Enable Turbo Deploy? (WARNING: Doesn't ask user for confirmation)", font=(self.font, 10))
        turbo_deploy_text.grid(row=0, column=1, columnspan=5, sticky=tk.W)
        #########################################################################################################
        dhcp_arp_options_frame = tk.Frame(master=self.options_frame, relief=tk.GROOVE, borderwidth=2)   # Create frame from grouping turbo options.
        dhcp_arp_options_frame.grid(row=5, rowspan=2, column=0, columnspan=5, sticky=tk.NSEW)
        dhcp_arp_options_frame.rowconfigure(self.grid_size, weight=1)
        dhcp_arp_options_frame.columnconfigure(self.grid_size, weight=1)
        enable_dhcp_snooping_checkbox = tk.Checkbutton(master=dhcp_arp_options_frame, variable=self.dhcp_snooping_check, onvalue=True, offvalue=False)
        enable_dhcp_snooping_checkbox.grid(row=0, rowspan=1, column=0, columnspan=1, sticky=tk.E)
        dhcp_vlan_text = tk.Label(master=dhcp_arp_options_frame, text="Enable DHCP Snooping on vlans", font=(self.font, 10))
        dhcp_vlan_text.grid(row=0, column=1, columnspan=2, sticky=tk.W)
        self.dhcp_snoop_vlan_entry = tk.Entry(master=dhcp_arp_options_frame, width=10, validate="all", validatecommand=(dhcp_arp_options_frame.register(lambda input:True if (re.match("^[0-9,-]*$", input) or input == "") else False), "%P"))
        self.dhcp_snoop_vlan_entry.grid(row=0, column=3, sticky=tk.W)
        self.dhcp_snoop_vlan_entry.insert(0, "1,2-4,5")
        self.disable_dhcp_snooping_option82_checkbox = tk.Checkbutton(master=dhcp_arp_options_frame, variable=self.dhcp_snooping_option82_check, onvalue=True, offvalue=False)
        self.disable_dhcp_snooping_option82_checkbox.grid(row=1, rowspan=1, column=0, columnspan=1, sticky=tk.E)
        dhcp_option82_text = tk.Label(master=dhcp_arp_options_frame, text="Disable option82 injection. (Improves compatibility with DHCP servers)", font=(self.font, 10))
        dhcp_option82_text.grid(row=1, column=1, columnspan=4, sticky=tk.W)
        self.enable_arp_inspection_checkbox = tk.Checkbutton(master=dhcp_arp_options_frame, variable=self.arp_inspection_check, onvalue=True, offvalue=False)
        self.enable_arp_inspection_checkbox.grid(row=2, rowspan=1, column=0, columnspan=1, sticky=tk.E)
        arp_vlan_text = tk.Label(master=dhcp_arp_options_frame, text="Enable ARP inspection on vlans", font=(self.font, 10))
        arp_vlan_text.grid(row=2, column=1, columnspan=2, sticky=tk.W)
        self.arp_inspection_vlan_entry = tk.Entry(master=dhcp_arp_options_frame, width=10, validate="all", validatecommand=(dhcp_arp_options_frame.register(lambda input:True if (re.match("^[0-9,-]*$", input) or input == "") else False), "%P"))
        self.arp_inspection_vlan_entry.grid(row=2, column=3, sticky=tk.W)
        self.arp_inspection_vlan_entry.insert(0, "1,2-4,5")
        #########################################################################################################

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
        This function is triggered everytime the Deploy button is pressed and continues executing until the
        deploy is finished. The process for this button click triggers a new thread that send the given 
        commands to all selected devices.

        Parameters:
        -----------
            None
        
        Returns:
        --------
            Nothing
        """        
        # Check if a deploy has already been started.
        if not self.already_deploying:
            # Clear class deploy vars.
            self.already_deploying = False
            self.directory_name = ""
            self.selected_devices = []
            self.usernames = []
            self.passwords = []
            self.enable_secrets = []
            self.command_text = ""
            self.user_result = False
            self.bad_deploys = []
            self.deploy_devices_total_count = 0
            self.exit_messages = {"info": [], "warning": [], "error": [], "critical": []}
            self.switch_output = []
            self.deploy_thread = None
            self.deploy_device = None

            # Create deploy output directory.
            self.directory_name = f"deploy_outputs/{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
            os.makedirs(self.directory_name, exist_ok=True)

            # Loop through each boolean value and match it to the device ip.
            self.selected_devices = []
            for selected, device in zip(self.switch_tree_check_values, self.selection_devices_list):
                # Get the selected devices status and append them to a list if true.
                if selected.get():
                    # Insert object at beginning of list. This effectively reverses the list, so we can just go through is from the beginning when deploying commands.
                    self.selected_devices.insert(0, device)
                    # Count number of deploy devices.
                    self.deploy_devices_total_count += 1

            # Get username and password lists.
            self.usernames = [username.get() for username in self.username_entrys]
            self.passwords = [password.get() for password in self.password_entrys]
            self.enable_secrets = [secret.get() for secret in self.secret_entrys]
            # Remove empty passwords.
            for i, password in enumerate(self.passwords):
                # Check length.
                if len(password) <= 0:
                    # Remove list item.
                    self.usernames.pop(i)
                    self.passwords.pop(i)
                    self.enable_secrets.pop(i)

            #  Get commands from textbox.
            self.command_text = self.command_textbox.get('1.0', tk.END)

            # Check if selected devices list is empty.
            if len(self.selected_devices) > 0:
                # Check to make sure the user entered something for the vlan change if selected.
                if len(self.command_text) <= 1:
                    # Print log and show messagebox to user.
                    self.logger.info("Command textbox is empty!")
                    messagebox.showwarning(title="Warning!", message="Command textbox is empty!")
                    # Set toggle to keep deploy from continuing.
                    self.user_result = False
                elif self.change_vlan_check.get() and (len(self.vlan_old_entry.get()) <= 0 or len(self.vlan_new_entry.get()) <= 0):
                    # Print log and show messagebox.
                    self.logger.warning("Can't start deploy because no vlans have been entered to change! If you don't want to enter vlans, then uncheck the box in the options pane.")
                    messagebox.showwarning(message="Can't start deploy because the user didn't specify old and new vlans even though the checkbox was ticked.")
                    # Set toggle to keep deploy from continuing.
                    self.user_result = False
                elif self.dhcp_snooping_check.get() and len(self.dhcp_snoop_vlan_entry.get()) <= 0:
                    # Print log and show messagebox.
                    self.logger.warning("Can't start deploy because no vlans have been entered to snoop on!")
                    messagebox.showwarning(message="Can't start deploy because no vlans have been entered to snoop on! You must enter vlans like: 1,2-3,4")
                    # Set toggle to keep deploy from continuing.
                    self.user_result = False
                elif self.arp_inspection_check.get() and len(self.arp_inspection_vlan_entry.get()) <= 0:
                    # Print log and show messagebox.
                    self.logger.warning("Can't start deploy because no vlans have been entered to do arp inspection on!")
                    messagebox.showwarning(message="Can't start deploy because no vlans have been entered to do arp inspection on! You must enter vlans like: 1,2-3,4")
                    # Set toggle to keep deploy from continuing.
                    self.user_result = False
                else:
                    # Before starting threads, ask user if they are sure they want to continue.
                    self.logger.info("Asking user if they are sure they want to start the deploy process...")
                    self.user_result = messagebox.askyesno(title="ATTENTION!", message="Are you sure you want to start the deploy process? This will make changes to the devices!")
                    # Display warning messages about DHCP Snooping.
                    if self.dhcp_snooping_check.get() and self.user_result:
                        self.logger.warning("Asking user if they are ABSOLUTELY SURE they want to enable DHCP snooping on switches...")
                        self.user_result = messagebox.askyesno(message="WARNING!!! By enabling DHCP snooping all dhcp offers from non-trunk ports will be blocked. After enabling this feature, you must manually log into the switch connected to your DHCP server and run 'ip dhcp snooping trust' on the switchport interface. If you don't, then no hosts will be able to receive a new DHCP address! ARE YOU ABSOLUTELY SURE YOU WANT TO CONTINUE?")
                        if self.arp_inspection_check.get() and self.user_result:
                            self.logger.warning("Asking user if they are ABSOLUTELY SURE they want to enable ARP inspection on switches...")
                            self.user_result = messagebox.askyesno(message="WARNING!!! By enabling ARP snooping all non DHCP devices will be blocked from connecting to the network! After enabling this feature, you must manually log into EVERY SWITCH and run 'ip arp inspection trust' on the ports you trust or add a manual binding in the 'ip source' table. If you don't, then any hosts with a static IP will not be able to join the network! ARE YOU ABSOLUTELY SURE YOU WANT TO CONTINUE?")
            else:
                # Print log and show messagebox.
                self.logger.warning("Can't start deploy because no devices have been selected.")
                messagebox.showwarning(message="Can't start deploy because no devices have been selected.")
                # Set toggle to keep deploy from continuing.
                self.user_result = False

        # Check user is sure they want to start deploy.
        if self.user_result:
            if not self.already_deploying:
                # Toggle that deploy has been started and print log.
                self.already_deploying = True
                self.logger.info("Command deploy has been started!")
                # Set window size. Take it out of fullscreen.
                self.window.wm_state('iconic')
                # Print log.
                self.logger.info(f"NetCommander will be running these commands on the selected switches: \n{self.command_text}")

            # Check if thread is finished.
            if self.deploy_thread is None:
                # Get the next up switch.
                self.deploy_device = self.selected_devices.pop(0)
                # Reset output variables.
                self.exit_messages = {"info": [], "warning": [], "error": [], "critical": []}
                self.switch_output = []
                # Start a new thread that connects to each ip and runs the given commands.
                self.deploy_thread = Thread(target=self.deploy_button_back_process, args=[self.command_text, self.deploy_device, self.usernames, self.passwords, self.enable_secrets, self.enable_telnet_check.get(), self.force_telnet_check.get(), self.change_vlan_check.get(), self.vlan_old_entry.get(), self.vlan_new_entry.get(), self.toggle_voice_vlan_check.get(), self.dhcp_snooping_check.get(), self.dhcp_snoop_vlan_entry.get(), self.dhcp_snooping_option82_check.get(), self.arp_inspection_check.get(), self.arp_inspection_vlan_entry.get(), self.exit_messages, self.switch_output])
                self.deploy_thread.start()
            elif not self.deploy_thread.is_alive():
                # Close thread.
                self.deploy_thread.join()

                print(self.exit_messages)

                # Check if we got any error messages.
                show_output_box = True
                if any(len(val[1]) > 0 for val in self.exit_messages.items()):
                    # Loop through keys in exit message dictionary.
                    for key in self.exit_messages.keys():
                        # Check message type and show messagebox to user.
                        if key == "info":
                            # Show message to user.
                            for info_message in self.exit_messages[key]:
                                # Show info to user.
                                messagebox.showinfo(title="Info", message=info_message)
                        if key == "warning":
                            # Show message to user.
                            for warning_message in self.exit_messages[key]:
                                # Show info to user.
                                messagebox.showwarning(title="Warning", message=warning_message)
                        if key == "error":
                            # Show message to user.
                            for error_message in self.exit_messages[key]:
                                # Show info to user.
                                messagebox.showerror(title="Error", message=error_message)
                                # Set toggle to not show switch output.
                                show_output_box = False
                        if key == "critical":
                            # Show message to user.
                            for critical_message in self.exit_messages[key]:
                                # Show info to user.
                                messagebox.showcritical(title="CRITICAL", message=critical_message)
                                # Set toggle to not show switch output.
                                show_output_box = False

                # Check if we should still show output text and get confirmation from user.
                if show_output_box:
                    # Show the output to the user and ask if it is correct.
                    text_popup(f"Command Output for {self.deploy_device['hostname']}, {self.deploy_device['ip_addr']}", self.switch_output[0], x_grid_size=10, y_grid_size=10)
                    # Write output to a file.
                    with open(f"{self.directory_name}/{self.deploy_device['hostname']}({self.deploy_device['ip_addr']}).txt", 'w+') as file:
                        for line in self.switch_output[0]:
                            file.write(line)

                # Check if turbo deploy is enabled.
                if self.turbo_deploy_check.get():
                    correct_output = True
                    continue_deploy = True
                else:
                    # Check if we should still show oyutput text and get confimation from user.
                    if show_output_box:
                        # Ask the user if the output is correct.
                        correct_output = messagebox.askyesno(title=f"Confirm correct output for {self.deploy_device['hostname']}, {self.deploy_device['ip_addr']}", message="Is this output correct? Its output will be saved to the deploy_outputs folder.")
                    
                    # Ask the user if they want to continue.
                    continue_deploy = messagebox.askyesno(title="Continue deploy?", message="Would you like to continue the command deploy?")

                # If the output was incorrect add the switch to a list.
                if not correct_output:
                    self.bad_deploys.append(self.deploy_device)
                # If the user doesn't want to continue the deploy then stop looping.
                if not continue_deploy:
                    # Print log.
                    self.logger.info("The deploy has been canceled by the user.")

                # Check if the command deployment is done.
                if len(self.selected_devices) <= 0 and self.already_deploying or not continue_deploy:
                    # Print bad deploy devices to logs.
                    self.logger.info(f"Unable to fully deploy commands to these devices: {self.bad_deploys}")
                    # Print log and show messagebox stating the deploy has finished.
                    self.logger.info(f"The command deploy has finished! {len(self.bad_deploys)} out of {self.deploy_devices_total_count} did not successfully execute the given commands. Opening window with the IPs now...")
                    messagebox.showinfo(message=f"The command deploy has finished! {len(self.bad_deploys)} out of {self.deploy_devices_total_count} did not successfully execute the given commands.")
                    # Check if we need to open the window.
                    if len(self.bad_deploys) > 0:
                        text_popup(title="Bad Deploy Devices", text=[f"{self.deploy_device['ip_addr']} - {self.deploy_device['hostname']}\n" for self.deploy_device in self.bad_deploys])

                    # Reset deploy toggle.
                    self.already_deploying = False
                else:
                    # Set deploy thread to None.
                    self.deploy_thread = None
        else:
            # Print log.
            self.logger.info("Command deploy has been canceled.")

    def deploy_button_back_process(self, command_text, device, usernames, passwords, enable_secrets, enable_telnet, force_telnet, change_vlan_check, vlan_old_entry, vlan_new_entry, toggle_voice_vlan_check, dhcp_snooping_check, dhcp_snoop_vlan_entry, dhcp_snooping_option82_check, arp_inspection_check, arp_inspection_vlan_entry, exit_messages, switch_output) -> None:
        """
        Helper function for Deploy Button, deploys commands to a single device in a new thread.
        """
        # Create instance variables.
        output = ""
        # Attempt to login to the given device.
        ssh_device = ssh_autodetect_info(usernames, passwords, enable_secrets, enable_telnet, force_telnet, device["ip_addr"])
        connection = ssh_telnet(ssh_device, enable_telnet, force_telnet, store_config_info=True)
        
        try:
            # Check if device connection was successful.
            if connection is not None and connection.is_alive():
                # Check the privilege level of our connection. Must be 15 to execute all commands.
                if "15" in connection.send_command("show privilege"):
                    # Print log.
                    self.logger.info(f"Connected to device {device['ip_addr']}. Running commands...")

                    # Run the commands on the switch and show output, then ask the user if the output looks good.
                    for line in command_text.splitlines():
                        # Catch timeouts.
                        try:
                            # Send the current command to the switch.
                            output += f"\n{connection.find_prompt()}{line}\n"
                            output += connection.send_command(line, expect_string="#")
                        except ReadTimeout:
                            self.logger.warning(f"Couldn't get command output for {device['ip_addr']}. It is likely the commands still ran.")
                            exit_messages["warning"].append(f"Couldn't get command output for {device['ip_addr']} running command {line}. However, it is likely the command still ran and the console just took too long to print output.")
                        except Exception as e:
                            self.logger.error(f"Netmiko ERROR: {e}")

                    # Check if the user has enabled vlan changing.
                    if change_vlan_check:
                        # Get vlan new and old numbers from the user.
                        vlan_command_text = change_port_vlans(vlan_old_entry, vlan_new_entry, toggle_voice_vlan_check, ssh_device)                                

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
                                exit_messages["warning"].append(f"Couldn't get command output for {device['ip_addr']} running command {line}. However, it is likely the command still ran and the console just took too long to print output.")

                        # Append some newlines to the output to keep it pretty.
                        output += "\n\n"

                    # Check if the user has enabled DHCP snooping option.
                    if dhcp_snooping_check:
                        # Get vlan new and old numbers from the user.
                        vlan_command_text = setup_dhcp_snooping_on_trunks(ssh_device, dhcp_snoop_vlan_entry, dhcp_snooping_option82_check)                                

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
                                exit_messages["warning"].append(f"Couldn't get command output for {device['ip_addr']} running command {line}. However, it is likely the command still ran and the console just took too long to print output.")
                    
                        # Append some newlines to the output to keep it pretty.
                        output += "\n\n"

                        # Check if the user has enabled ARP inspection option.
                        if arp_inspection_check:
                            # Get vlan new and old numbers from the user.
                            vlan_command_text = setup_dynamic_arp_inspection_on_trunks(ssh_device, arp_inspection_vlan_entry)                                

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
                                    exit_messages["warning"].append(f"Couldn't get command output for {device['ip_addr']} running command {line}. However, it is likely the command still ran and the console just took too long to print output.")

                            # Append some newlines to the output to keep it pretty.
                            output += "\n\n"
                else:
                    # Print log and show messagebox.
                    self.logger.error(f"Insignificant privilege level to safely run all commands on {device['ip_addr']}. Skipping and adding to bad deploy list...")
                    exit_messages["error"].append(f"Insignificant privilege level to safely run all commands on {device['ip_addr']}. The device will be skipped and marked as a bad deploy.")

                # Disconnection from device.
                connection.disconnect()
            else:
                # Print log and show messagebox.
                self.logger.error(f"Failed to connection to {device['ip_addr']}")
                exit_messages["error"].append(f"Couldn't connect to {device['ip_addr']}. Moving on to next device.")
        except OSError:
            self.logger.warning(f"Couldn't get command output for {device['ip_addr']}. Paramiko reported the socket as being closed. It is recommended that you rerun your commands on this switch!")
            exit_messages["warning"].append("Couldn't get command output for {device['ip_addr']}. Paramiko reported the socket as being closed. It is recommended that you rerun your commands on this switch!")

        # Append compiled output to passed in variable.
        switch_output.append(output)

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

        #######################################################################
        # Update options entries and checkboxes.
        #######################################################################
        # Vlan change entries.
        if not self.change_vlan_check.get() and self.vlan_entries_state_enabled:
            # Disable elements.
            self.vlan_old_entry.configure(state="disable")
            self.vlan_new_entry.configure(state="disable")
            self.access_vlan_radio_select.configure(state="disable")
            self.voice_vlan_radio_select.configure(state="disable")
            # Update toggle var.
            self.vlan_entries_state_enabled = False
        elif self.change_vlan_check.get() and not self.vlan_entries_state_enabled:
            # Disable elements.
            self.vlan_old_entry.configure(state="normal")
            self.vlan_new_entry.configure(state="normal")
            self.access_vlan_radio_select.configure(state="normal")
            self.voice_vlan_radio_select.configure(state="normal")
            # Update toggle var.
            self.vlan_entries_state_enabled = True
        # DHCP entries and checkboxes.
        if not self.dhcp_snooping_check.get() and self.dhcp_snoop_vlan_entry_state_enabled:
            # Disable elements.
            self.dhcp_snoop_vlan_entry.configure(state="disable")
            self.disable_dhcp_snooping_option82_checkbox.configure(state="disable")
            self.enable_arp_inspection_checkbox.configure(state="disable")
            self.arp_inspection_vlan_entry.configure(state="disable")
            # Update toggle var.
            self.dhcp_snoop_vlan_entry_state_enabled = False
        elif self.dhcp_snooping_check.get() and not self.dhcp_snoop_vlan_entry_state_enabled:
            # Enable elements.
            self.dhcp_snoop_vlan_entry.configure(state="normal")
            self.disable_dhcp_snooping_option82_checkbox.configure(state="normal")
            self.enable_arp_inspection_checkbox.configure(state="normal")
            # Only enable this entry if the arp checkbox is also checked.
            if self.arp_inspection_check.get():
                self.arp_inspection_vlan_entry.configure(state="normal")
            # Update toggle var.
            self.dhcp_snoop_vlan_entry_state_enabled = True
        # ARP entry.
        if not self.arp_inspection_check.get() and self.arp_inspection_vlan_entry_state_enabled:
            # Disable elements.
            self.arp_inspection_vlan_entry.configure(state="disable")
            # Update toggle var.
            self.arp_inspection_vlan_entry_state_enabled = False
        elif self.arp_inspection_check.get() and not self.arp_inspection_vlan_entry_state_enabled:
            # Enable elements.
            self.arp_inspection_vlan_entry.configure(state="normal")
            # Update toggle var.
            self.arp_inspection_vlan_entry_state_enabled = True

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

        # Check if the deploy toggle is currently set.
        if self.already_deploying:
            # Check toggle.
            if self.deploy_frames_state_enabled:
                # Disable frames so user can't jack with the important controls.
                self.disable_children(self.options_frame)
                self.disable_children(self.creds_frame)
                # Set toggle.
                self.deploy_frames_state_enabled = False

            # If so, call the deploy callback function to handle threads and deploy logic.
            self.deploy_button_callback()
        elif not self.deploy_frames_state_enabled:
            # Reenabled frames.
            self.enable_children(self.options_frame)
            self.enable_children(self.creds_frame)
            # Set deploy frame toggle.
            self.deploy_frames_state_enabled = True
            # Switch all check and entry toggles to be the opposite of what they are. THis makes the current widgets disable.
            # Vlan change entries.
            if not self.change_vlan_check.get():
                self.vlan_entries_state_enabled = True
            else:
                self.vlan_entries_state_enabled = False
            # DHCP entries and checkboxes.
            if not self.dhcp_snooping_check.get():
                self.dhcp_snoop_vlan_entry_state_enabled = True
            else:
                self.dhcp_snoop_vlan_entry_state_enabled = False
            # ARP entry.
            if not self.arp_inspection_check.get():
                self.arp_inspection_vlan_entry_state_enabled = True
            else:
                self.arp_inspection_vlan_entry_state_enabled = False

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

    def enable_children(self, parent):
        """
        Enable all tkinter widgets contained within the given parent frame or window.

        Parameters:
        -----------
            parent - The parent widget.
        Returns:
        --------
            Nothing
        """
        for child in parent.winfo_children():
            wtype = child.winfo_class()
            if wtype not in ('Frame','Labelframe','TFrame','TLabelframe'):
                child.configure(state='normal')
            else:
                self.enable_children(child)

    def disable_children(self, parent):
        """
        Disable all tkinter widgets contained within the given parent frame or window.

        Parameters:
        -----------
            parent - The parent widget.
        Returns:
        --------
            Nothing
        """
        for child in parent.winfo_children():
            wtype = child.winfo_class()
            if wtype not in ('Frame','Labelframe','TFrame','TLabelframe'):
                child.configure(state='disable')
            else:
                self.disable_children(child)

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