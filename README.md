# PythonNetCommander
This project can automagically discover all cisco switches that are communicable through the same management vlan and run a user defined set of commands on each one. Each time the given set of commands is executed on a switch it shows the output and asks the user if the result is acceptable. It also utilizes an outside-in layered approach, so it starts running commands on the 'furthest hop' switches and works it's way back to the specified 'closest hop' switch. This attempts to ensure that if anything goes wrong with one switch, you won't loose connection to the other, still functioning switches.

## Intended Use
This program was originally created to aid in running a relatively small set of switch commands on a large network. For example, if a large network's switches are using telnet, this program could be used to execute the nessesary commands to configure a massive number of devices to use SSH with a RADIUS or TACACS+ server. This program should not be used to configure single switches or switches that are not running Cisco IOS.


```diff
-RUN WITH CAUTION. YOU CAN EASILY MESS UP MULTIPLE SWITCH CONFIGS WITH THIS PROGRAM.-
```
The commands are ran on the switches selected by the user in order of 'hop' distance, starting from the furthest switch out. All program and switch console outputs are saved to timestamped log files in the program's directory.
![tempsnip](https://user-images.githubusercontent.com/26121134/199790942-d48e6570-5b31-40e9-9af9-e9d89e0efa27.png)

During automatic switch discovery, the program generates a topology layout of the network to help the user decided what switches they want the commands to run on.
![graph](https://user-images.githubusercontent.com/26121134/199791146-60a1784e-6fbc-44f9-a4ce-1f64dd3c3e87.PNG)


## Install
This python program has been compiled with pyinstaller, which turns python code into a .exe file. It includes all dependencies and a python 3.8.10 installation in the executable, so no third-party applications need to be installed.
  1) Download the latest release.
      - onefile.zip offers a more simplistic application executable, but runs at a slower speed. This is because the whole application and its dependencies are compiled
        into a single file.
      - onefolder.zip offers faster execution, but the application directory is more cluttered.
  2) Copy a shortcut to the desktop and open the program.
  
  OR download and install the setup .exe file.

## Compile
If your wanting to make code changes or just want the latest build, you'll need to setup the pip environment and use pyinstaller to recompile the executable.
### Environment Setup and Build
  1) Clone/download and unzip the project 
  2) Install the pip environment
      - Navigate to the project directory
      - Install the pip environment ```pipenv install```
      - Enter the pip environment ```pipenv shell```
  3) Run [PyInstaller](https://pyinstaller.org/en/stable/) using the command-line or by running the included script.
      - Click on the settings drop-down and import the pyinstaller.json file located in this project's root directory. This will import all the necessary settings for           compiling.
      - Select whether you want to build the program to onefile or onefolder and choose an output directory.
      - Click "convert .py to .exe"
      - Once the program has finished compiling, copy the logging_config.yaml file into the output directory.
      
### More Info
All actions, warnings, and errors are saved to a timestamped logs folder in the root directory of the appliction. If the program crashes or does something unexpected, please open a new issue here on github and include the log in the issue.
