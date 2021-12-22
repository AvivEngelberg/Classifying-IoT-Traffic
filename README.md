# smart-home
This project is licensed under the terms of the Apache license 2.0 license.

If you publish any results with data collected using this software, please cite the following paper:

**Classification of Encrypted IoT Traffic Despite Padding and Shaping.** Aviv Engelberg, Avishai Wool. [arXiv Preprint](https://arxiv.org/abs/2110.11188)

We examined a wide range of smart devices from diffeernt classes (cameras, plugs, bulbs, etc.) coming from well known vendors (e.g. Amazon, Belkin, etc).
The devices' traffic traces are from the open sources of [Sivanathan et al.](https://ieeexplore.ieee.org/document/8116438) and [Trimananda et al.](https://www.ndss-symposium.org/ndss-paper/packet-level-signatures-for-smart-home-devices/). 
You may use different traffic traces from other sources, but please make sure to follow the usage instructions below.
The developed software is intended to examine padding and shaping mitigations applied on a tested network traffic and demonstrate how we could learn and simulate it similarly ourselves in order to gain information about the tested network.
This work is developed for research purposes, do not try to use it for malicious purposes. 
## Usage Instructions

To execute the code use run
```
python detectorIoT.py [action=None][directoryName=None]
```
The argument action specify the desired action that you want to apply on the traffic. Its value should be an integer between 0--8. 
The argument directoryName should only be specified if use the value 0 for action. It specifies the directory's name in which the file will be saved.

Always run the code from the same working directory as it depends on directories it creates and reads from during its execution.
The code will create the following directories inside the working directory at its first execution: "Saved Simulations","Upload Simulations","Tested Traffic","SavedSimulations\Subsets".

1. "Saved Simulations": Directory where all the simulations done during execution are saved.
2. "Upload Simulations": Directory from which simulations are uploaded and used for the program's purpose.
3. "SavedSimulations\Subsets": Sub-directoyry inside "SavedSimulations" in which devices' subsets' simulations are saved.
4. "Tested Traffic": Directory in which tested traffic traces will be stored.
# First Run
When you execute the program for the first time run it without arguments
```
python detectorIoT.py 
```
This will create directories 1-4.

# After your first run
Make sure to create directory for each candidate device in your network inside the working directory.
Inside each device's directory put its learning traffic trace, i.e., trace realted to the device's outbound traffic. 
Inside the "Tested Traffic" directory put the tested traffic traces. Note: trace files are either a ".pcap" or ".pcapang" file.
Make sure that all of the above traces have unique names, as the program use them as identifiers for the simulations.

After you did this, you would need to execute
```
python detectorIoT.py 0 [directoryName]
```
This will create the sub-diretory directoryName inside the "Saved Simulations" directory. 
It would then create simulation file for any learning and test trace file and save it inside this sub-directory. 
Simulation files contain data related to the devices' outbound traffic after applying the padding and shaping on it.
Simulations related to learning traces (aka learnt simulations) will help us classify the tested traffic, and those related to tested traces (aka tested simulations) will imitate real-time tested traffic protected with padding and shaping that we would like to examine and classify.
Since our program is only intended to simulate and imitate real padded and shaped traffic and not create actual pcap files after applying these mitigations, we also simulate the tested traces ourselves and then save them obfuscated in a simulation file.

Each simulation contains the following fields:
1. frequencies- a dictionary that has packet sizes as keys and their associated frequencies as values
2. realPeriods- for learning trace it contains the device's real-traffic periods; for tested trace (because we want to obfuscate it) it stores all the device's periods
3. fakePeriods- for learning trace it contains the device's only-cover-traffic periods; for tested trace it's an empty list
4. deviceNumber- for learning trace it stores the device's number, for tested trace (because we want to obfuscate it) it stores arbitrarily (-1)
5. isLearntSimulation- for learning trace it is True, for tested trace it is False
6. file- the name of the learning/test trace file 
7. q- for learning trace it stores the value of q used in the simulation, for tested trace (because we want to obfuscate it) it stores arbitrarily (-1)
8. W- for learning trace it stores the value of W used in the simulation, for tested trace (because we want to obfuscate it) it stores arbitrarily (-1)

# Regular Useage
This program allows to save simulations and do various detections on the tested traffic.
Notice that the second argument directoryName is required only in case where action=0.
For the recommended duration times of the traces, refer to [arXiv Preprint](https://arxiv.org/abs/2110.11188).
Following are specified all the possible actions you can apply on the traffic:
0. Arguments: action=0,directoryName=yourSavedDirectoryName. Action: Saving inside sub-directory directoryName in "Saved Simulations", simulation file for any learning trace file in the devices directories and for any test trace file in the directory "Tested Traffic".
1.Argument:action=1. Assumptions: Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device, and at least one tested simulation of a device. Action: Based on the learnt simulations, returning to stdout classification of which device is active in every tested simulation file.
2.
3.
4.
5.
6.
7.
8.








