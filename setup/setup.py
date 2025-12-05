#!/usr/env/bin/python
"""
setup.py is used to prepare an empty directory for pentesting.
It does not have to be run if you have set up Pentest Island
before and are running from the expected directory.

This utility should:
    - Prepare a pentest and tools directory
    - Download a selection of tools into /tools
    - apt install a selection of tools to /bin
    - download pipx and pipx some tools
    - Generate venvs for relevant tools
    - Wish you Luck

You can also provide a tools directory for setup to audit.
setup.py will look for the following:
    - do cloned git repos for tools exist
    - do apt installed packages exist
    - is there a DEDICATED VENV FOLDER NAMED 'venvs'
        `- if there is not, THE TOOL WILL MAKE IT
    - does the venv folder have all the necessary envs
        `- if they don't match format 'toolenv',
        `- setup will make them. (e.g. responderenv)
"""

import sys
import os
import venv
import subprocess
from pathlib import Path
import json
import shutil
import appdirs

from art.art import robot

 
# Internal Setup Function. Triggered by Menu
class IntSetup:
    # Determines ToolDir Existence
    # Returns tool directory absolute path 
    def intSetupStart():
        toolDirExists = input("""
    =====================================================================
            Great! This Internal Pentest Should be Set Up Fast!
                    Do you have a tool directory?
                        0.) No
                        1.) Yes
                                                    (B)ack Up
                                                    (Q)uit
    """)
        
        match toolDirExists:
            case "0":
                print("Okay! We will build your tools in ./tools.")
                toolDir = os.getcwd + "/tools"
            case "1":
                toolDir = input("Please give me the absolute path of your tool dir: ")
                if os.path.isdir(toolDir):
                    print("That directory looks good. Sending bots there now...")
                else:
                    print("Can't find that directory. Maybe check the spelling? I'm sending you back...")
                    IntSetup.intSetupStart()
            case "q"|"Q":
                sys.exit()
            case "b"|"B":
                GenSetup.menu()
        return(toolDir)
    
    # Determines which tools must be checked for.
    # OUT: array of tools to be checked for
    def getIntTools():
        config = GenSetup.getToolsConfig()
        return [tool for tool in config['tools'] if tool['engagement'] == 'i' or tool['engagement'] == 'a']

class ExtSetup:
    # External Setup Function. Triggered by Menu
    # Returns tool directory absolute path
    def extSetupStart():
        toolDirExists = input("""
    =====================================================================
            Great! This External Pentest Should be Set Up Fast!
                    Do you have a tool directory?
                        0.) No
                        1.) Yes
                                                    (B)ack Up
                                                    (Q)uit
    """)
        
        match toolDirExists:
            case "0":
                print("Okay! We will build your tools in ./tools.")
                toolDir = os.getcwd() + "/tools"
            case "1":
                toolDir = input("Please give me the absolute path of your tool dir: ")
                if os.path.isdir(toolDir):
                    print("That directory looks good. Sending bots there now...")
                else:
                    print("Can't find that directory. Maybe check the spelling? I'm sending you back...")
                    IntSetup.intSetupStart()
            case "q"|"Q":
                sys.exit()
            case "b"|"B":
                GenSetup.menu()
        return(toolDir)
    
    # Determines which tools should be checked/installed
    # OUT: array of tools to be checked/installed
    def getExtTools():
        config = GenSetup.getToolsConfig()
        return [tool for tool in config['tools'] if tool['engagement'] == 'e' or tool['engagement'] == 'a']

class GenSetup:
    # Main Menu Display
    # TODO: Fix all case matches.
    def menu():
        robot()
        testType = input("""
    =====================================================================
        The Robot Factory can Build Anything you Need...
                Is this an:
                        1.) Internal Pentest
                        2.) External Pentest
                                                (R)eturn to Island
                                                (Q)uit
    """)
        match testType:
            case "1":
                return 1
            case "2":
                return 2
            case "r"|"R":
                return 3
            case "q"|"Q":
                sys.exit()
            case _:
                print("Menu only accepts ints, R or Q.")
    
    # Determines if User Config Exists for Tool Install List
    # If not found in ~/.config/ptisland, will make dir and file.
    # Loads config to memory for use in setup functions.
    # OUT: json of tools and their properties.
    def getToolsConfig():
        # Gets dir for config to see if exists
        configDir = Path(appdirs.user_config_dir("ptisland"))
        configDir.mkdir(parents=True,exist_ok=True)
        userConfig = configDir / "toolsList.json"
        # If no config, makes one
        if not userConfig.exists():
            defaultConfig = Path(__file__).parent / "data" / "toolsList.json"
            shutil.copy(defaultConfig, userConfig)
        # Loads config to be used with setup functions.
        with open(userConfig, 'r') as f:
            return json.load(f)
    
    # checks installed tools based on input array to determine.
    # IN: Array of tools to check, tool dir
    # OUT: Array of tools to install
    def checkInstalled(tools, toolDir):
        installs = []
        for tool in tools:
            # if tool is expected callable from cli we try
            if tool['pacman'] == 'apt' or 'pipx':
                cmd = [f'{tool['name']}', '--version']
                result = subprocess.run(cmd)
                if result.returncode == 127: # 'command not found'
                    installs.append(tool)
                else:
                    pass # No Action Needed
            elif tool['pacman'] == 'git':
                # Check to see if git folder exists in tool dir
                if os.path.isdir(toolDir + f"{tool['name']}/"):
                    pass # No action needed
                else:
                    installs.append(tool)

    # IN: install candidates (array), tool dir
    # OUT: Your tools are installed
    # Moves to tool dir to clone repos and then returns to cwd 
    def installTools(tools, toolDir):
        startDir = os.getcwd()
        os.chdir(toolDir)
        for tool in tools:
            if tool['pacman'] == 'apt':
                cmd = ['apt','install',f'{tool['download']}']
                result = subprocess.run(cmd)
                if result.returncode == 0:
                    print(f"{tool['name']} installed")
                else:
                    print(f"error installing {tool['name']}.")
            elif tool['pacman'] == 'pipx':
                cmd = ['pipx','install',f'{tool['download']}']
                result = subprocess.run(cmd)
                if result.returncode == 0:
                    print(f"{tool['name']} installed")
                else:
                    print(f"error installing {tool['name']}.")
            elif tool['pacman'] == 'git':
                cmd = ['git','clone',f'{tool['download']}']
                result = subprocess.run(cmd)
                if result.returncode == 0:
                    print(f"{tool['name']} installed")
                else:
                    print(f"error installing {tool['name']}.")
            else:
                print(f"install method not yet written for {tool['name']}")
            os.chdir(startDir)

    # Generates python virtual environments
    # for tools that need them. It does this
    # in the cwd by making /venvs
    def makeVenvs(tools):
        cwd = os.getcwd()
        if Path(cwd + 'venvs/').exists():
            os.chdir('venvs')
        else:
            os.mkdir('venvs')
            os.chdir('venvs')
        cwd = os.getcwd()
        for tool in tools:
            venvname = f'{tool['name']}Env'
            venvpath = cwd + f"{venvname}"
            if venvpath.exists():
                shutil.rmtree(venvpath)
            venv.create(venvname,with_pip=True)
        
    # Updates venvs to have dependencies installed
    # IN: install list (tools), array
    # OUT: your venvs are installed
    def updateVenvs(tools, toolDir):
        cwd = os.getcwd() # Should be /home/user/venvs
        for tool in tools:
            venvname = f'{tool['name']}Env'
            pippath = cwd + f"{venvname}" / "bin" / "pip"
            result = subprocess.run([
                pippath, "install", "-r", f"{toolDir}/{tool['name']}/requirements.txt"
            ], check=True, capture_output=True, text=True)
        os.chdir('../') # take you back up to main dir


def flow():
    testType = GenSetup.menu()
    if testType == 1:
        toolDir = IntSetup.intSetupStart()
        installTools = IntSetup.getIntTools()
        GenSetup.installTools(installTools, toolDir)
        GenSetup.makeVenvs(installTools)
        GenSetup.updateVenvs(installTools, toolDir)
        print("""
=====================================================================\
              Setup should now be completed! Go check everything
              because I didn't put any error checking in this thing.
""")
        return

    elif testType == 2:
        toolDir = ExtSetup.extSetupStart()
        installTools = ExtSetup.getExtTools()
        GenSetup.installTools(installTools, toolDir)
        GenSetup.makeVenvs(installTools)
        GenSetup.updateVenvs(installTools, toolDir)
        print("""
=====================================================================\
              Setup should now be completed! Go check everything
              because I didn't put any error checking in this thing.
""")
        return
    elif testType == 3:
        return
    else:
        print("You should literally never see this. You fucked up.")
        sys.exit()
