import re
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

interface_vlan_change_list = ["Gi0/1", "Twe2/0/8", "Twe2/0/9", "Twe2/0/10", "Hu2/0/1", "Hu2/0/2", "Gi1/0/1", "Gi1/0/2", "Gi1/0/4", "Gi1/0/5", "Gi1/0/6", "Gi1/0/7", "Gi1/0/8", "Gi1/0/9", "Gi1/0/11", "Gi1/1/1", "Tw2/0/3", "Tw2/0/4", "Tw2/0/6", "Te1/1/1", "Te1/1/2", "Te1/1/4", "Po1"]

vlan_command_text = ""
output = ""
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
    interface_ranges = ""
    range_counter = 0
    for key in interface_port_types.keys():
        # Get the interface list.
        interface_numbers = interface_port_types[key]
        interface_numbers = list(map(int, interface_numbers))
        # Group numbers.
        interface_numbers = list(find_ranges(interface_numbers))
        print(interface_numbers)
        # Parse command text.
        for range in interface_numbers:
            # Check if we have hit five ranges.
            if range_counter >= 5:
                # Remove last comma and space from interface range text.
                interface_ranges = interface_ranges[:-2]
                # Build commands list for vlan change.
                vlan_command_text += f"end\nconf t\nint range {interface_ranges}\n"
                vlan_command_text += f"sw acc vlan 1\n"
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
    vlan_command_text += f"end\nconf t\nint range {interface_ranges}\n"
    vlan_command_text += f"sw acc vlan 1\n"
    # Add end to exit global config mode.
    vlan_command_text += "end\n"

    print(vlan_command_text)