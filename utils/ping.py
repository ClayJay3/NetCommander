# Import required packages.
import subprocess
import platform
import logging
import socket
from multiprocessing.pool import ThreadPool
from typing import Tuple

# Create constants.
PING_THREADS = 100

def ping(ip_or_hostname) -> Tuple[bool, str, str]:
    """
    This function takes in a machines ip or hostname and returns if it is reachable
    and resolve its ip and domainname.

    Parameters:
    -----------
        ip_or_hostname - The machines IP address or hostname on the network.

    Returns:
    --------
        Tuple[bool - is reachable?, str - IP adress, str - hostname]
    """
    # Create instance variables.
    logger = logging.getLogger(__name__)
    reachable = False
    ip_addr = None
    hostname = None

    # Check if given ip is not empty.
    if len(ip_or_hostname) > 0:
        # Ping commands will be different if we are on linux or windows.
        try:
            if platform.system() == "Linux":
                # Ping the machine.
                response = subprocess.Popen("ping -c 1 " + ip_or_hostname, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                response.wait()
                response = response.poll()
                # Check the response.
                if response == 0:
                    # Set reachable var.
                    reachable = True
                    # Try to resolve both the IP and hostname.
                    ip_addr = socket.gethostbyname(ip_or_hostname)
                    hostname, _, _ = socket.gethostbyaddr(ip_or_hostname)
                    # Print host is up.
                    logger.info(f"Ping of {ip_addr}: Host {hostname} is up!")
                else:
                    # Set reachable var.
                    reachable = False
                    # Print host id down.
                    logger.warning(f"Unable to talk to {ip_or_hostname}")
            else:
                # Ping the machine.
                response = subprocess.Popen("ping -n 1 " + ip_or_hostname, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                response.wait()
                response = response.poll()
                # Check the response.
                if response == 0:
                    # Set reachable var.
                    reachable = True
                    # Try to resolve hostname, must catch this because it throws errors if it fails.
                    try:
                        # Try to resolve both the IP and hostname.
                        ip_addr = socket.gethostbyname(ip_or_hostname)
                        hostname, _, _ = socket.gethostbyaddr(ip_or_hostname)
                        hostname = "asdf"
                    except Exception:
                        # Set hostname equal to ip address.
                        ip_addr = ip_or_hostname
                        hostname = ip_addr
                    # Print host is up.
                    logger.info(f"Ping of {ip_addr}: Host {hostname} is up!")
                else:
                    # Set reachable var.
                    reachable = False
                    # Print host id down.
                    logger.warning(f"Unable to talk to {ip_or_hostname}")

            return reachable, ip_addr, hostname
        except Exception as exception:
            # Print debug.
            logger.critical(f"Something weird happened while pinging {ip_or_hostname}.", exc_info=exception, stack_info=True)


def ping_of_death(text, ip_list) -> None:
    """
    This function looks at the given list of strings containing ips and pings each one to see which ones are reachable.

    Parameters:
    -----------
        text - A list containing strings of ips.
        ip_list - The list to store all the ip info inside.
    
    Returns:
    --------
        Nothing
    """
    # Create method instance variables.
    thread_pool = ThreadPool(PING_THREADS)
    logger = logging.getLogger(__name__)

    # Check if the textbox actually contains something.
    if len(text[0]) > 0:
        # Loop through each line and try to ping it in a new thread.
        ips = thread_pool.map_async(ping, text)

        # Wait for pool threads to finish.
        thread_pool.close()
        thread_pool.join()

        # Get results from pool.
        for address in ips.get():
            ip_list.append(address)
    else:
        logger.warning("Textbox is empty! You must enter switch addresses in the textbox.")