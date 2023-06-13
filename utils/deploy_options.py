import re
import logging
import more_itertools as mit

def find_ranges(iterable):
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

def change_port_vlans(old_vlan, new_vlan, toggle_voice_vlans, ssh_device):
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    command_text = "end\nconf t\n"

    # Loop through interfaces and get a list of interfaces with interfaces on VLAN1.
    interface_vlan_change_list = []
    for interface in ssh_device["interfaces"]:
        # Catch key errors for malformed interface output.
        try:
            # Check the interface vlan.
            if int(interface["switchport access vlan"]) == int(old_vlan) and interface["vlan_status"] == old_vlan and not interface["switchport mode trunk"] and ("Ap" not in interface["name"]) and "trunk" not in interface["vlan_status"]:
                interface_vlan_change_list.append(interface["name"])
        except KeyError as error:
            logger.error(f"KeyError ({error}): An interface output for {ssh_device['hostname']} was not received properly, skipping...")

    # Check that we have at least 1 interface to change.
    if len(interface_vlan_change_list) > 0:
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
        interface_ranges = ""
        range_counter = 0
        for key in interface_port_types.keys():
            # Get the interface list.
            interface_numbers = interface_port_types[key]
            interface_numbers = list(map(int, interface_numbers))
            # Group numbers.
            interface_numbers = list(find_ranges(interface_numbers))
            # Parse command text.
            for range in interface_numbers:
                # Check if we have hit five ranges.
                if range_counter >= 5:
                    # Remove last comma and space from interface range text.
                    interface_ranges = interface_ranges[:-2]
                    # Build commands list for vlan change.
                    command_text += f"int range {interface_ranges}\n"
                    
                    # Check if we are changing access vlans or voice vlans.
                    if toggle_voice_vlans:
                        command_text += f"sw acc vlan {new_vlan}\n"
                    else:
                        command_text += f"sw voice vlan {new_vlan}\n"


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
        command_text += f"int range {interface_ranges}\n"
        # Check if we are changing access vlans or voice vlans.
        if toggle_voice_vlans:
            command_text += f"sw acc vlan {new_vlan}\n"
        else:
            command_text += f"sw voice vlan {new_vlan}\n"
        # Add end to exit global config mode.
        command_text += "end\n"

    return command_text

def setup_dhcp_snooping_on_trunks(ssh_device, snoop_vlans, disable_option_82=True):
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    command_text = ""

    # Loop through interfaces and get a list of interfaces with interfaces on VLAN1.
    interface_change_list = []
    for interface in ssh_device["interfaces"]:
        # Catch key errors for malformed interface output.
        try:
            # Check the interface vlan.
            if interface["vlan_status"] == "trunk" and ("Ap" not in interface["name"]):
                interface_change_list.append(interface["name"])
        except KeyError as error:
            logger.error(f"KeyError ({error}): An interface output for {ssh_device['hostname']} was not received properly, skipping...")

    # Check that we have at least 1 interface to change.
    if len(interface_change_list) > 0:
        # Convert the list into more compact ranges, CiscoIOS can only handle 5-8 ranges.
        interface_port_types = {}
        for interface in interface_change_list:
            # Cutoff first two or three letters of interface and add key to dictionary if it doesn't exist. If it doesn exist, then append it to the list in the dictionary.
            key = re.split("/", interface[::-1], 1)[-1][::-1]
            if key not in interface_port_types.keys():
                interface_port_types[key] = [re.split("/|Po", interface)[-1]]
            else:
                interface_port_types[key].append(re.split("/|Po", interface)[-1])

        # Check if snoop_vlans contains something.
        if len(snoop_vlans) > 0:
            # Build global DHCP snooping commands.
            command_text += f"end\nconf t\n"
            
            # Group the interfaces together to be more efficient.
            interface_ranges = ""
            range_counter = 0
            for key in interface_port_types.keys():
                # Get the interface list.
                interface_numbers = interface_port_types[key]
                interface_numbers = list(map(int, interface_numbers))
                # Group numbers.
                interface_numbers = list(find_ranges(interface_numbers))
                # Parse command text.
                for range in interface_numbers:
                    # Check if we have hit five ranges.
                    if range_counter >= 5:
                        # Remove last comma and space from interface range text.
                        interface_ranges = interface_ranges[:-2]
                        # Build commands list for vlan change.
                        command_text += f"int range {interface_ranges}\n"
                        command_text += f"ip dhcp snooping trust\n"

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
            command_text += f"int range {interface_ranges}\n"
            command_text += "ip dhcp snooping trust\n"
            command_text += "end\nconf t\n"

            # Disable option82 insertion if enabled.
            if disable_option_82:
                command_text += "no ip dhcp snooping information option\n"
            # Turn on snooping for vlans.
            command_text += f"ip dhcp snooping\n"
            command_text += f"ip dhcp snooping vlan {snoop_vlans}\n"

            # Add end to exit global config mode.
            command_text += "end\n"

    return command_text

def setup_dynamic_arp_inspection_on_trunks(ssh_device, dai_vlans):
    # Create instance variables and objects.
    logger = logging.getLogger(__name__)
    command_text = ""

    # Loop through interfaces and get a list of interfaces with interfaces on VLAN1.
    interface_change_list = []
    for interface in ssh_device["interfaces"]:
        # Catch key errors for malformed interface output.
        try:
            # Check the interface vlan.
            if interface["vlan_status"] == "trunk" and ("Ap" not in interface["name"]):
                interface_change_list.append(interface["name"])
        except KeyError as error:
            logger.error(f"KeyError ({error}): An interface output for {ssh_device['hostname']} was not received properly, skipping...")

    # Check that we have at least 1 interface to change.
    if len(interface_change_list) > 0:
        # Convert the list into more compact ranges, CiscoIOS can only handle 5-8 ranges.
        interface_port_types = {}
        for interface in interface_change_list:
            # Cutoff first two or three letters of interface and add key to dictionary if it doesn't exist. If it doesn exist, then append it to the list in the dictionary.
            key = re.split("/", interface[::-1], 1)[-1][::-1]
            if key not in interface_port_types.keys():
                interface_port_types[key] = [re.split("/|Po", interface)[-1]]
            else:
                interface_port_types[key].append(re.split("/|Po", interface)[-1])

        # Check if the dai_vlans list contains something.
        if len(dai_vlans) > 0:
            # Build global ARP inspection commands.
            command_text += f"end\nconf t\n"
            
            # Group the interfaces together to be more efficient.
            interface_ranges = ""
            range_counter = 0
            for key in interface_port_types.keys():
                # Get the interface list.
                interface_numbers = interface_port_types[key]
                interface_numbers = list(map(int, interface_numbers))
                # Group numbers.
                interface_numbers = list(find_ranges(interface_numbers))
                # Parse command text.
                for range in interface_numbers:
                    # Check if we have hit five ranges.
                    if range_counter >= 5:
                        # Remove last comma and space from interface range text.
                        interface_ranges = interface_ranges[:-2]
                        # Build commands list for vlan change.
                        command_text += f"int range {interface_ranges}\n"
                        command_text += f"ip arp inspection trust\n"
                        
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
            command_text += f"int range {interface_ranges}\n"
            command_text += "ip arp inspection trust\n"
            command_text += "end\nconf t\n"

            # Enable ARP inspection for vlans.
            command_text += f"ip arp inspection vlan {dai_vlans}\n"

            # Add end to exit global config mode.
            command_text += "end\n"

    return command_text