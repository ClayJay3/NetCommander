# Import required packages and modules.
from ast import Tuple
from functools import partial
import re
import time
import logging
from multiprocessing.pool import ThreadPool
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException, ReadTimeout
from netmiko.ssh_dispatcher import ConnectHandler

# Define Constants.
MAX_DISCOVERY_THREADS = 100

# Create global file variables.
ip_discovery_list = []
export_info_list = []
license_info = []

def cdp_auto_discover(ip_list, usernames, passwords, enable_secrets, enable_telnet=False, force_telnet=False, export_info=False, recursion_level=0) -> list:
    """
    This function takes in a list of strings containing the ip addresses to start auto discovery with.
    Then new processes are spawned that run a show cdp neighbors command and parse the output to find more connected switches.
    Those new switches then go through the same process until no more switches are discoverd.

    This method is recursive.

    Parameters:
    -----------
        list(string) - A list of the initially known switch IPs.
        list(string) - A list of the username creds.
        list(string) - A list of the password creds.
        boolean - Whether or not to try telnet if ssh fails.
        boolean - Whether of not to try and export info.

    Returns:
    --------
        list(string) - A list of strings containg the new switch IPs. Duplicated are removed.
    """
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)

    # Check if length of IP list is greater than zero.
    if len(ip_list) == 0:
        # Print log.
        logger.info("Discovery has reached the end of the network, closing recursive branches now.")

        # Loop through export info and license info.
        for export_data in export_info_list:
            # Add empty license info in case nothing matches.
            export_data["license_state"] = "NULL"
            export_data["license_expire_period"] = "NULL"
            export_data["license_info"] = "NULL"
            for license_data in license_info:
                # Check if the license hostname appears in export hostname. If so, then append license data to dictionary.
                if license_data["ip_addr"] == export_data["ip_addr"]:
                    export_data["license_state"] = license_data["license_state"]
                    export_data["license_expire_period"] = license_data["expire_period"]
                    export_data["license_info"] = license_data["raw_output"]

        # Clear license_info arrray.
        license_info.clear()

        # Return if we hit the end of the switch line.
        return ip_discovery_list, export_info_list
    else:
        # Create a new thread pool and get cdp info.
        pool = ThreadPool(MAX_DISCOVERY_THREADS)
        # Loop through each ip and create a new thread to get info.
        result_ips = pool.map_async(partial(get_cdp_neighbors_info, usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_info), ip_list)
        # Wait for pool threads to finish.
        pool.close()
        pool.join()

        # Get resulting IPs and filter out duplicates.
        new_ips = []
        for discovered_ip_addrs, device_infos in result_ips.get():
            for ip_addr in discovered_ip_addrs:
                if not ip_addr in ip_discovery_list:
                    # Append them to discover list. Also create a new list with this recursion layers new unique IPs.
                    ip_discovery_list.append(ip_addr)
                    new_ips.append(ip_addr)
            for info in device_infos:
                # Add device info to info list if not already there.
                if export_info and len(info) > 0 and info["hostname"] != "NULL" and not info in export_info_list:
                    # Use list comprehension to check of the hostname has already been put into the dictionary list.
                    hostnames = [key_val["hostname"] for key_val in export_info_list]
                    # If not already there insert it.
                    if info["hostname"] not in hostnames:
                        # Add recursion level to info.
                        info["recursion_level"] = recursion_level
                        # Finally, append to list.
                        export_info_list.append(info)

        # Print log.
        logger.info(f"Discovered IPs {new_ips} from the following devices: {ip_list}")

        # Increment recursion level.
        recursion_level += 1

        # Recursion baby.
        return cdp_auto_discover(new_ips, usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_info, recursion_level)

def get_cdp_neighbors_info(usernames, passwords, enable_secrets, enable_telnet, force_telnet, export_info, ip_addr) -> Tuple(list):
    """
    This function opens a new ssh connection with the given ip and gets cdp neighbors info.

    Parameters:
    -----------
        usernames - The login username list
        passwords - The login password list
        enable_secrets - The secrets for enable mode.
        enable_telnet - Toggle telnet login attempts.
        ip_addr - The IP address of the switch.

    Returns:
    --------
        list - A list containing the connected cdp devices IP info.
        device_info - A list containing other device info.
    """
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    connection = None
    cdp_neighbors_result_ips = []
    device_infos = []

    # Check if IP length is greater than zero.
    if len(ip_addr) > 0:
        for username, password, secret in zip(usernames, passwords, enable_secrets):
            # If secret is empty use normal password.
            if len(secret) <= 0:
                secret = password

            # Create device dictionary.
            remote_device = {"device_type": "autodetect", "host": ip_addr, "username": username, "password": password, "secret": secret}
            # If the device is not a switch codemiko will crash.
            # Attempt to open SSH connection first, then Telnet.
            try:
                # Open new ssh connection with switch.
                connection = ConnectHandler(**remote_device)
            except NetmikoTimeoutException:
                # Check if telnet connections have been enabled.
                if enable_telnet or force_telnet:
                    try:
                        # Change device type to telnet.
                        remote_device["device_type"] = "cisco_ios_telnet"
                        # Open new ssh connection with switch.
                        connection = ConnectHandler(**remote_device)
                    except (NetmikoAuthenticationException, ConnectionRefusedError, TimeoutError, Exception):
                        # Do nothing. Errors are expected, handling is slow.
                        pass
            except (NetmikoAuthenticationException, ConnectionRefusedError, TimeoutError):
                # Check if force telnet connections have been enabled.
                if force_telnet:
                    try:
                        # Change device type to telnet.
                        remote_device["device_type"] = "cisco_ios_telnet"
                        # Open new ssh connection with switch.
                        connection = ConnectHandler(**remote_device)
                    except (NetmikoAuthenticationException, ConnectionRefusedError, TimeoutError, Exception):
                        # Do nothing. Errors are expected, handling is slow.
                        pass
            except (ConnectionRefusedError, Exception):
                # Do nothing. Errors are expected, handling is slow.
                pass

            # Configure terminal properties if connection is alive.
            if connection is not None and connection.is_alive():
                # If the enable password is wrong, then netmiko will throw an error.
                try:
                    # Get priviledged terminal.
                    connection.enable()
                except ReadTimeout:
                    # Close connection and set connection back to None.
                    connection.disconnect()
                    connection = None
                    # Print log.
                    logger.warning(f"Unable to access {ip_addr}! \x1b[31;1mThere may be more devices behind this switch. To find these devices, please setup {ip_addr} like the other accessible devices.")

            # Check if connection was actually opened.
            if connection is not None and connection.is_alive():
                # Get parent hostname.
                prompt = connection.find_prompt()[:-1]
                # Sometimes switches or login prompt will confuse netmiko. Retry until we found the actual prompt.
                retries = 0
                while "http" in prompt and retries < 10:
                    # Find prompt.
                    prompt = connection.find_prompt()[:-1]
                    # Sleep for output.
                    time.sleep(1)

                # Create base dictionary.
                license_dict = {"ip_addr": ip_addr, "license_state": "NULL", "expire_period": "NULL", "raw_output": "NULL"}
                
                # Catch any readtimeouts.
                try:
                    # Get license information about parent switch.
                    license_output = connection.send_command("show license | include Feature|Period|State")
                    # Check if the command output failed.
                    if len(license_output.splitlines()) <= 3:
                        # Run different show license command.
                        license_output = connection.send_command("show license all | include Status:")
                        # Check if it failed again, and run different command.
                        if len(license_output.splitlines()) <= 3:
                            # Run different show license command.
                            license_output = connection.send_command("show license right-to-use")
                            # Check if the command ran successfully.
                            if len(license_output) > 3:
                                # Store raw license output.
                                license_dict["raw_output"] = license_output

                                # Parse output.
                                # Split output by newlines. Cutoff first two.
                                license_output = license_output.splitlines()[2:]
                                # Loop through license slots.
                                names = ""
                                periods = ""
                                for line in license_output:
                                    # Check if we hit the end of the list.
                                    if "--------" not in line:
                                        # Split line sections up by spaces.
                                        info = re.split(" +", line)
                                        # Add data to var.
                                        names += info[1] + f"({info[2]})" + " | "
                                        periods += info[-1] + " | "
                                    else:
                                        # Stop looping.
                                        break
                                # Append data to license dictionary.
                                license_dict["license_state"] = names
                                license_dict["expire_period"] = periods

                        else:
                            # Store raw license output.
                            license_dict["raw_output"] = license_output

                            # Parse ouput.
                            # Split output by newlines.
                            license_output = license_output.splitlines()
                            # The first line should be the register status.
                            license_dict["license_state"] = license_output[0]
                            # The second value should be the expiration time.
                            license_dict["expire_period"] = license_output[1]
                    else:
                        # Store raw license output.
                        license_dict["raw_output"] = license_output

                        # Parse output.
                        # Split output by keyword INDEX.
                        license_output = license_output.split("Index")
                        # Use the section with more info.
                        license_output = license_output[1].splitlines() if len(license_output[1].splitlines()) >= 3 else license_output[2].splitlines()
                        # Check for expire status.
                        for line in license_output:
                            # Get license period.
                            if "Period left" in line:
                                # Remove unneccesary keywords and remove leading and trailing whitespace.
                                line = line.replace("Period left:", "").strip()
                                # Replace commas and tabs with dashes and spaces.
                                line = line.replace(",", " -")
                                line = line.replace("\t", " ")
                                # Append info to license dictionary.
                                license_dict["expire_period"] = line
                            # Get license state.
                            if "License State" in line:
                                # Remove uneccesary keywords and remove leading and trailing whitespace.
                                line = line.replace("License State:", "").strip()
                                # Replace commas and tabs with dashes and spaces.
                                line = line.replace(",", " -")
                                line = line.replace("\t", " ")
                                # Append info the license dictionary.
                                license_dict["license_state"] = line
                except ReadTimeout:
                    # Nothing to do.
                    pass
                except Exception as error:
                    # Print logger error.
                    logger.warning(f"Difficulty parsing switch license output from {ip_addr}: {error}") 

                # Append information to the list.
                license_info.append(license_dict)

                # Catch any parse errors for cdp info.
                try:
                    #######################################################################
                    # Get the IP and hostname info.
                    #######################################################################
                    # Run cdp command to get relavant info.
                    output = connection.send_command("show cdp neighbors detail")#| sec Device|Management|Capabilities|Version|Interface")

                    # Parse output, split string based on the Device keyword.
                    device_cdps = re.split("Device", output)
                    # Loop through device strings.
                    for device in device_cdps:
                        # Split lines.
                        info = device.splitlines()

                        # Create device info variables.
                        device_info = {}
                        hostname = "NULL"
                        addr = "NULL"
                        local_trunk_interface = "NULL"
                        software_name = "NULL"
                        version = "NULL"
                        platform = "NULL"
                        is_wireless_ap = False
                        is_switch = False
                        is_router = False
                        is_phone = False
                        is_camera = False
                        parent_addr = "NULL"
                        parent_host = "NULL"
                        parent_trunk_interface = "NULL"
                        # Loop through each line and find the device info.
                        for line in info:
                            # Find device IP address.
                            if ("IP address:" in line or "IPv4 Address" in line) and addr == "NULL":
                                # Replace keyword.
                                addr = line.replace("IP address: ", "").strip()
                                addr = addr.replace("IPv4 Address:", "").strip()
                            # Attempt to determine if the device is a switch.
                            if "Platform" in line and "Switch" in line:
                                is_switch = True
                                if "Router" in line:
                                    is_router = True
                            # Find device type:
                            if "AIR" in line or "Trans-Bridge" in line:
                                is_wireless_ap = True
                                is_switch = False
                            # Check if export info is toggled on.
                            if export_info and len(addr) > 0:
                                # Find device hostname.
                                if "ID:" in line and hostname == "NULL":
                                    # Replace keyword.
                                    line = line.replace("ID:", "")
                                    # Remove any parenthesis and text inside parenthesis.
                                    line = re.sub("[\(\[].*?[\)\]]", "", line)
                                    # Remove whitespace and store data.
                                    hostname = line.strip()

                                # Find device software version info.
                                if "Version :" not in line and "Version:" not in line and "Version" in line:
                                    # Split line up by commas.
                                    line = re.split(",", line)
                                    # Loop through and find software name and version.
                                    for i, section in enumerate(line):
                                        # First line will be the software name.
                                        if i == 0:
                                            software_name = section
                                        # Find version.
                                        if "Version" in section:
                                            # Remove keyword.
                                            section = section.replace("Version", "")
                                            # Strip whitespace and store.
                                            version = section.strip()

                                # Find platform.
                                if "Platform" in line:
                                    # Remove keyword and other garbage after the comma
                                    line = line.replace("Platform:", "")
                                    line = line.split(",", 1)[0]
                                    # Remove whitespace and store.
                                    platform = line.strip()

                                # Find the local trunk interface and parent interface.
                                if "Interface:" in line:
                                    # Split line by comma.
                                    line = re.split(",", line)
                                    # Get and store the local and remote interface.
                                    remote_interface = line[0]
                                    local_interface = line[1]
                                    # Remove unessesary keyword arguments.
                                    remote_interface = remote_interface.replace("Interface:", "")
                                    local_interface = local_interface.replace("Port ID (outgoing port):", "")
                                    # Remove whitespace and store.
                                    local_trunk_interface = local_interface.strip()
                                    parent_trunk_interface = remote_interface.strip()

                        # If both the software name and version were unable to be found assume device is not a switch, but a phone.
                        if export_info:
                            if software_name == "NULL" and version == "NULL":
                                is_switch = False
                                # If platform is null, then it's not a phone.
                                if platform != "NULL" and platform != "Linux":
                                    is_phone = True

                            # If it's not any of these, then assume it's a camera.
                            if not any([is_router, is_switch, is_wireless_ap, is_phone]):
                                is_camera = True

                            # Append parent address to device.
                            parent_addr = ip_addr
                            parent_host = prompt

                        # Add info to dictionary.
                        device_info["hostname"] = hostname
                        device_info["ip_addr"] = addr
                        device_info["local_trunk_interface"] = local_trunk_interface
                        device_info["software_name"] = software_name
                        device_info["version"] = version
                        device_info["platform"] = platform
                        device_info["is_wireless_ap"] = is_wireless_ap
                        device_info["is_switch"] = is_switch
                        device_info["is_router"] = is_router
                        device_info["is_phone"] = is_phone
                        device_info["is_camera"] = is_camera
                        device_info["parent_addr"] = parent_addr
                        device_info["parent_host"] = parent_host
                        device_info["parent_trunk_interface"] = parent_trunk_interface

                        if "mgmt" not in local_trunk_interface and "mgmt" not in parent_trunk_interface:
                            # Remove leading whitespace and append final ip to the cdp info list.
                            if addr != "NULL" and is_switch:
                                cdp_neighbors_result_ips.append(addr)

                            # Append device to the device infos list.
                            if export_info and device_info["hostname"] != "NULL" and device_info not in device_infos:
                                device_infos.append(device_info)

                    # Close ssh connection.
                    connection.disconnect()
                    # Stop looping through for loop.
                    break
                except ReadTimeout:
                    # Nothing to do.
                    pass
                except Exception as error:
                    # Print logger error.
                    logger.warning(f"Difficulty parsing switch cdp output from {ip_addr}: {error}") 

    return cdp_neighbors_result_ips, device_infos

def clear_discoveries() -> None:
    """
    This method clears the global lists.

    Parameters:
    -----------
        None

    Returns:
    --------
        Nothing
    """
    # Clear global lists.
    ip_discovery_list.clear()
    export_info_list.clear()
