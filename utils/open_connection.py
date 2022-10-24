# Import required packages and modules.
from cmd import PROMPT
import re
import logging
from functools import partial
from multiprocessing.pool import ThreadPool
import string
from tkinter import messagebox
import netmiko
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
from netmiko.ssh_dispatcher import ConnectHandler

# Create constants.
SSH_THREADS = 100

def ssh_autodetect_info(usernames, passwords, enable_secrets, enable_telnet, force_telnet, ip_addr, result_info=None) -> str:
    """
    This method will attempt to autodetect the switch device info using netmiko's
    ssh_autodetect

    Parameters:
    -----------
        usernames - The username creds list to try and login with.
        passwords - The password creds list to try and login with.
        enable_secrets - The secret list to try and enable with.
        enable_telnet - Boolean val to enable telnet support.
        force_telnet - Boolean val to force telnet fallback.
        ip_address - The ip address of the device to try to connect to.
        result_info - This can be used as a reference variable if this function is running in
                    a thread and it's return values can't be retrieved.

    Returns:
    --------
        device - A dictionary containing info about the switch like (model, hostname, firmware version, and neighbors)
    """
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    remote_device = None
    ssh_connection = None

    # Try each username.
    for username, password, secret in zip(usernames, passwords, enable_secrets):
        # If secret is empty use normal password.
        if len(secret) <= 0:
            secret = password

        # Create device dictionary.
        remote_device = {"device_type": "autodetect", "host": ip_addr, "username": username, "password": password, "secret": secret}
        # If the device is not a switch codemiko will crash.
        # Attempt to open SSH connection first, then Telnet.
        try:
            # Print logging info.
            logger.info(f"Autodetecting model and opening connection for {ip_addr}")
            # Open new ssh connection with switch.
            ssh_connection = ConnectHandler(**remote_device)
        except NetmikoTimeoutException:
            # Check is telnet is enabled.
            if enable_telnet or force_telnet:
                # Print log.
                logger.warning(f"Unable to connect to device {ip_addr} with SSH. Trying telnet...")
                try:
                    # Change device type to telnet.
                    remote_device["device_type"] = "cisco_ios_telnet"
                    # Open new ssh connection with switch.
                    ssh_connection = ConnectHandler(**remote_device)
                except NetmikoAuthenticationException:
                    # Print log
                    logger.warning(f"Failed to login to device {ip_addr}. Trying next available username and password.")
                except Exception:
                    # Print log.
                    logger.error(f"Device {ip_addr} refused the connection.")
            else:
                # Print log.
                logger.warning(f"Unable to connect to device {ip_addr} with SSH. Skipping TELNET as it is not enabled...")
        except NetmikoAuthenticationException:
            # Check if force telnet is enabled.
            if force_telnet:
                # Print log.
                logger.warning(f"Couldn't authenticate with {ip_addr} even though SSH is enabled. Trying telnet...")
                try:
                    # Change device type to telnet.
                    remote_device["device_type"] = "cisco_ios_telnet"
                    # Open new ssh connection with switch.
                    ssh_connection = ConnectHandler(**remote_device)
                except NetmikoAuthenticationException:
                    # Print log
                    logger.critical(f"Couldn't authenticate with {ip_addr} through SSH or TELNET. Both are enabled, possible security risk!")
                except Exception:
                    # Print log.
                    logger.error(f"Device {ip_addr} refused the connection.")
            else:
                # Print log
                logger.warning(f"SSH is enabled, but still failed to login to device {ip_addr}. Trying next available username and password.")
        except Exception:
            # Print log.
            logger.error(f"Device {ip_addr} refused the connection.")

        #######################################################################
        # Get the IP and hostname info.
        #######################################################################
        # Check if connection was successful.
        if ssh_connection is not None and ssh_connection.is_alive():
            try:
                # Print logging info.
                logger.info("Waiting for command prompt...")
                # Look for switch prompt.
                prompt = ssh_connection.find_prompt()
                # Print prompt.
                logger.info(f"Found prompt: {prompt}")
                # Take off # from prompt to get hostname.
                remote_device["host"] = prompt[:-1]
                # Store known ip address.
                remote_device["ip_address"] = ip_addr
                # Close connection.
                ssh_connection.disconnect()
                # Stop looping through for loop.
                break
            except ValueError:
                logger.error(f"Unable to find switch prompt for {ip_addr}")
        else:
            # Set default value.
            remote_device["ip_address"] = ip_addr
            remote_device["host"] = "Unable_to_Authenticate"

    # Store final device dict in result_info.
    result_info = remote_device

    return result_info

def ssh_autodetect_switchlist_info(usernames, passwords, enable_secrets, enable_telnet, force_telnet, ip_list, device_list) -> None:
    """
    This method will attempt to autodetect a list of switches device info using netmiko's
    ssh_autodetect.

    Parameters:
    -----------
        usernames - The username creds list to try and login with.
        passwords - The password creds list to try and login with.
        enable_secrets - The secret list to try and enable with.
        enable_telnet - Boolean val to enable telnet support.
        force_telnet - Boolean val to force telnet fallback.
        ip_list - The ip addresses of the device to try to connect to.
        device_list - The list to store the deivce info in. (Returned in same order as ip_list)

    Returns:
    --------
        Nothing
    """
    # Create method instance variables.
    thread_pool = ThreadPool(SSH_THREADS)
    logger = logging.getLogger(__name__)

    # Check if the ip list actually contains something.
    if len(ip_list) > 0:
        # Try to auth with one switch first.
        first_switch = ssh_autodetect_info(usernames, passwords, enable_secrets, enable_telnet, force_telnet, ip_list.pop(0))
        # Check if auth was successful.
        if first_switch["host"] != "Unable_to_Authenticate":
            # Append first device to device list.
            device_list.append(first_switch)

            # Loop through each line and try to ping it in a new thread.
            devices = thread_pool.map_async(partial(ssh_autodetect_info, usernames, passwords, enable_secrets, enable_telnet, force_telnet), ip_list)
            # Wait for pool threads to finish.
            thread_pool.close()
            thread_pool.join()

            # Get results from pool.
            for switch in devices.get():
                device_list.append(switch)
        else:
            # Print log.
            logger.warning("Can't authenticate with the given credentials. Please enter the correct username and password.")
            # Append none to device list.
            device_list.append(None)
    else:
        # Print log.
        logger.warning("No IPs were givin. Can't open any SSH sessions to autodetect.")

def ssh_telnet(device, enable_telnet, force_telnet, store_config_info=False) -> netmiko.ssh_dispatcher:
    """
    This method uses the given ip to open a new ssh connetion.

    Parameters:
    -----------
        device - A dictionary object containing the required keys and values to connect to the device.
        enable_telnet - Boolean val to enable telnet support.
        force_telnet - Boolean val to force telnet fallback.
        store_config_info - A boolean value that determines if config info is gathered and stored in the given dictionary.

    Returns:
    --------
        ssh_connection - The live connection object to the device.
    """
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    ssh_connection = None

    # Get device ip.
    ip_addr = device["ip_address"]

    # Only give connect handler what it needs.
    remote_device = {"device_type": device["device_type"], "host": ip_addr, "username": device["username"], "password": device["password"], "secret": device["secret"]}
    # If the device is not a switch codemiko will crash.
    # Attempt to open SSH connection first, then Telnet.
    try:
        # Print logging info.
        logger.info(f"Autodetecting model and opening connection for {ip_addr}")
        # Open new ssh connection with switch.
        ssh_connection = ConnectHandler(**remote_device)
    except NetmikoTimeoutException:
        # Check is telnet is enabled.
        if enable_telnet or force_telnet:
            # Print log.
            logger.warning(f"Unable to connect to device {ip_addr} with SSH. Trying telnet...")
            try:
                # Change device type to telnet.
                remote_device["device_type"] = "cisco_ios_telnet"
                # Open new ssh connection with switch.
                ssh_connection = ConnectHandler(**remote_device)
            except NetmikoAuthenticationException:
                # Print log
                logger.warning(f"Failed to login to device {ip_addr}. Trying next available username and password.")
            except Exception:
                # Print log.
                logger.error(f"Device {ip_addr} refused the connection.")
        else:
            # Print log.
            logger.warning(f"Unable to connect to device {ip_addr} with SSH. Skipping TELNET as it is not enabled...")
    except NetmikoAuthenticationException:
        # Check if force telnet is enabled.
        if force_telnet:
            # Print log.
            logger.warning(f"Couldn't authenticate with {ip_addr} even though SSH is enabled. Trying telnet...")
            try:
                # Change device type to telnet.
                remote_device["device_type"] = "cisco_ios_telnet"
                # Open new ssh connection with switch.
                ssh_connection = ConnectHandler(**remote_device)
            except NetmikoAuthenticationException:
                # Print log
                logger.critical(f"Couldn't authenticate with {ip_addr} through SSH or TELNET. Both are enabled, possible security risk!")
            except Exception:
                # Print log.
                logger.error(f"Device {ip_addr} refused the connection.")
        else:
            # Print log
            logger.warning(f"SSH is enabled, but still failed to login to device {ip_addr}. Trying next available username and password.")
    except Exception:
        # Print log.
        logger.error(f"Device {ip_addr} refused the connection.")

    # Configure terminal properties if connection is alive.
    if ssh_connection is not None and ssh_connection.is_alive():
        # If the enable password is wrong, then netmiko will throw an error.
        try:
            # Get priviledged terminal.
            ssh_connection.enable()

            # Tell switch to continuously print output.
            prompt = ssh_connection.find_prompt()
            ssh_connection.send_command("terminal length 0", expect_string=prompt)
            ssh_connection.send_command("set length 0", expect_string=prompt)

            # Store info if toggle is set.
            if store_config_info:
                # Get device interface, vlan, and config info.
                interfaces, vlans, config = get_config_info(ssh_connection)
                # Store info in device dictionary.
                device["interfaces"] = interfaces
                device["vlans"] = vlans
                device["config"] = config
        except (ReadTimeout, AttributeError):
            # Store default values in device dictionary.
            device["interfaces"] = []
            device["vlans"] = []
            device["config"] = []
            # Print log.
            logger.error(f"Unable to enter priviledged mode. The enable password is incorrect for device {device['ip_address']} {device['host']}.")
    else:
        # Set default value.
        remote_device["ip_address"] = ip_addr
        remote_device["host"] = "Unable_to_Authenticate"

    # Connect and return
    return ssh_connection

def get_config_info(connection) -> netmiko.ssh_dispatcher:
    """
    Gathers information on the devices interfaces, vlans, and raw config given a netmiko connection to it.

    Parameters:
    -----------
        connection - The netmiko connection session to the device.

    Returns:
        interfaces - A list containing info about the devices interfaces.
        vlans - A list containing info about the devices vlans.
        config - The raw config output from the device.
    """
    # Create instance variables.
    interfaces = []
    vlans = []
    config = "Unable to pull config from device. Check console output for errors. Try refreshing device info."
    logger = logging.getLogger(__name__)

    # This one gets complicated, just gonna try-catch it all.
    try:
        # Check if connection is good.
        if connection is not None and connection.is_alive():
            # Check permission level.
            priv_output = connection.send_command("show priv").split(" ")[-1].strip()
            if int(priv_output) >= 15:
                # Find prompt for connection.
                prompt = connection.find_prompt()

                ###########################################################################
                # Parse and store config.
                ###########################################################################
                # Get config output.
                config = connection.send_command("show run", expect_string=prompt)
                # Split config text into lines and remove first three.
                config = config.split("\n")[3:]
                # Reassemble.
                config_output = ""
                for line in config:
                    config_output += line + "\n"
                # Store config.
                config = config_output

                ###########################################################################
                # Parse and store interfaces output.
                ###########################################################################
                # Get interface output.
                interface_output = connection.send_command("show interface status", expect_string=prompt).strip()

                # Parse interface output.
                data_keys = re.split(" +", interface_output.splitlines()[0])
                int_output = re.split("\n\n", interface_output)[0].splitlines()[1:]
                interface_details = []
                for line in int_output:
                    # Split line by spaces.
                    line = re.split(" +", line)
                    # Check if the last element contains just SFP. If so, then join the last two elements together.
                    if line[-1] == "SFP" or line[-1] == "Present":
                        # Get the last two elements and add them together.
                        new_type = line.pop(-2) + " " + line.pop(-1)
                        # Reappend to line.
                        line.append(new_type)
                    # If the array is greater than a certain length, then the desc must have spaces.
                    if len(line) > 7:
                        # Break data back apart to isolate desc.
                        last_data = line[-5:]
                        first_data = [line[0]]
                        # Join desc back into a single string.
                        inbetween = [" ".join(line[1:-5])]
                        # Rebuild line.
                        line = first_data + inbetween + last_data
                    # If the array is less than a certain length, then the desc must be empty.
                    if len(line) < 7:
                        # Check if the interface is a port channel.
                        if "Po" not in line[0]:
                            # Break data back apart to isolate desc.
                            last_data = line[-5:]
                            first_data = [line[0]]
                            # Join desc back into a single string.
                            inbetween = [""]
                            # Rebuild line.
                            line = first_data + inbetween + last_data
                        else:
                            # Break data back apart to isolate desc.
                            last_data = line[-4:]
                            first_data = [line[0]]
                            # Join desc back into a single string.
                            inbetween = [""]
                            # Rebuild line.
                            line = first_data + inbetween + last_data + [""]
                    # Match/zip values into a dictionary with the keys being the labels from the first line.
                    interface_details.append(dict(zip(data_keys, line)))

                for interface_dict in interface_details:
                    # Even though we parsed all the data in the code above, we are just going to use two of the values for now.
                    interfaces.append({"name" : interface_dict["Port"], "vlan_status": interface_dict["Vlan"]})

                ## Get individual interface data.
                # Split up config by !.
                config_blocks = re.split("!+", config)

                interface_blocks = []
                # Loop through the split up config blocks and only keep the interface ones.          
                for block in config_blocks:
                    # Check if the block contains the word interface.
                    if "interface" in block:
                        # Remove first two chars from block.
                        block = block[1:]
                        # split block up by new lines.
                        block = block.splitlines()
                        # Append to list.
                        interface_blocks.append(block)
                
                # Loop through the interfaces and blocks and match them by name.
                for interface in interfaces:
                    for interface_data in interface_blocks:
                        # Get interface name.
                        name_data = re.split(" +", interface_data[0])[1]
                        block_name = name_data[:2] + name_data.translate(str.maketrans('', '', string.ascii_letters + "-"))
                        # Check if names are equal.
                        if interface["name"] == block_name:
                            # Add relevant info to the interface using the interface_data list.
                            description = ""
                            shutdown = False
                            switch_mode_access = False
                            switch_mode_trunk = False
                            spanning_tree_portfast = False
                            spanning_tree_bpduguard = False
                            switch_access_vlan = 0
                            switch_voice_vlan = 0
                            switch_trunk_vlan = 0


                            # Loop through each config line for the interface and get data.
                            for data in interface_data:
                                # Get Description info.
                                if "description" in data and description == "" and "macro" not in data:
                                    # Remove unneeded keyword from data.
                                    data = data.replace("description", "")
                                    # Remove trailing and leading spaces and set description equal to new data.
                                    description = data.strip()

                                # Get port shutdown info.
                                if "shutdown" in data and not "no shutdown" in data:
                                    # Set toggle.
                                    shutdown = True

                                # Check for sw mo acc interface flag.
                                if "switchport mode access" in data:
                                    # Set toggle.
                                    switch_mode_access = True

                                # Check for spanning tree.
                                if "spanning-tree portfast" in data:
                                    # Set toggle.
                                    spanning_tree_portfast = True
                                if "spanning-tree bpduguard enable" in data:
                                    # Set toggle.
                                    spanning_tree_bpduguard = True

                                # Check for trunk mode data.
                                if "switchport mode trunk" in data:
                                    # Set toggle.
                                    switch_mode_trunk = True

                                # Check for access, voicem, and trunk vlan number.
                                if "switchport access vlan" in data:
                                    # Remove all letters from data.
                                    data = data.translate(str.maketrans('', '', string.ascii_letters))
                                    # Remove trailing and leading whitespace and store.
                                    switch_access_vlan = data.strip()
                                if "switchport voice vlan" in data:
                                    # Remove all letters from data.
                                    data = data.translate(str.maketrans('', '', string.ascii_letters))
                                    # Remove trailing and leading whitespace and store.
                                    switch_voice_vlan = data.strip()
                                if "switchport trunk native vlan" in data:
                                    # Remove all letters from data.
                                    data = data.translate(str.maketrans('', '', string.ascii_letters))
                                    # Remove trailing and leading whitespace and store.
                                    switch_trunk_vlan = data.strip()

                                
                            # Add description to interface dictionary.
                            interface["description"] = description
                            interface["shutdown"] = shutdown
                            interface["switchport mode access"] = switch_mode_access
                            interface["switchport mode trunk"] = switch_mode_trunk
                            interface["spanning-tree portfast"] = spanning_tree_portfast
                            interface["spanning-tree bpduguard enable"] = spanning_tree_bpduguard
                            interface["switchport access vlan"] = switch_access_vlan
                            interface["switchport voice vlan"] = switch_voice_vlan
                            interface["switchport trunk native vlan"] = switch_trunk_vlan
                            interface["config_has_changed"] = False

                ###########################################################################
                # Parse and store vlan output.
                ###########################################################################
                # Add interface and vlan info to the switch device dictionary.
                vlan_output = connection.send_command("show vlan brief", expect_string=prompt)
                output_split = vlan_output.splitlines()[3:]
                # Loop through each line and get relavent data.
                for line in output_split:
                    # Check line validity.
                    if len(line) > 2:
                        # Split line into words at each whitespace.
                        line = re.split(" +", line)
                        # Check if vlan is active.
                        if len(line) >= 3 and "active" in line[2]:
                            # Get data.
                            vlan = line[0]
                            name = line[1]
                            # Append to vlan array.
                            vlans.append({"vlan" : vlan, "name" : name})

                ## Get individual interface data.
                # Split up config by !.
                config_blocks = re.split("!+", config)

                vlan_blocks = []
                # Loop through the split up config blocks and only keep the interface ones.          
                for block in config_blocks:
                    # Check if the block contains the word interface.
                    if "interface Vlan" in block:
                        # split block up by new lines and remove first line. (it's empty)
                        block = block.splitlines()[1:]
                        # Append to list.
                        vlan_blocks.append(block)
                
                # Loop through the vlans and blocks and match them by name.
                for vlan in vlans:
                    for vlan_data in vlan_blocks:
                        # Get vlan name.
                        name_data = re.split(" +", vlan_data[0])[1]
                        block_name = name_data.translate(str.maketrans('', '', string.ascii_letters + "-"))
                        # Check if names are equal.
                        if vlan["vlan"] == block_name:
                            # Add relevant info to the vlan using the vlan_data list.
                            description = ""
                            ip_addr = ""
                            shutdown = False

                            # Loop through each config line for the vlan and get data.
                            for data in vlan_data:
                                # Get Description info.
                                if "description" in data and description == "" and "macro" not in data:
                                    # Remove unneeded keyword from data.
                                    data = data.replace("description", "")
                                    # Remove trailing and leading spaces and set description equal to new data.
                                    description = data.strip()
                                # Get ip address info.
                                if not "no ip address" in data and "ip address" in data:
                                    # Remove uneeded keyword from data.
                                    data = data.replace("ip address", "")
                                    # Remove trailing and leading spaces and set new data.
                                    ip_addr = data.strip()
                                # Get vlan shutdown info.
                                if "shutdown" in data and not "no shutdown" in data:
                                    # Set toggle.
                                    shutdown = True
                                
                            # Add description to vlan dictionary.
                            vlan["description"] = description
                            vlan["ip address"] = ip_addr
                            vlan["shutdown"] = shutdown
                            vlan["config_has_changed"] = False
            else:
                # If the priv level is below 15, then print error.
                logger.critical("Could not escalate priviledges even though the enable secret is correct. Check the minimum privilege level for the vty connections in the configuration.")
                # Put flag in interface list.
                config = "Could not escalate priviledges even though the enable secret is correct. Check the minimum privilege level for the vty connections in the configuration.\nThis switch's config prevents this application from running properly."
    except Exception as error:
        # Print log.
        logger.error("Something goofy happened while updating switch configuration info: ", exc_info=error, stack_info=True)

    return interfaces, vlans, config