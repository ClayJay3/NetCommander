# PythonNetCrawler
It's universal, but probably only works for cisco switches. This project can export network maps, it provides a couple different robust methods of discovery.

## Install
This python program has been compiled with pyinstaller, which turns python code into a .exe file. It includes all dependencies and a python 3.8.10 installation in the executable, so no third-party applications need to be installed.
  1) Download the latest release.
      - onefile.zip offers a more simplistic application executable, but runs at a slower speed. This is because the whole application and its dependencies are compiled
        into a single file.
      - onefolder.zip offers faster execution, but the application directory is more cluttered.
  2) Copy a shortcut to the desktop and open the program.

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
