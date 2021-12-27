# Classifying IoT Traffic
This project is licensed under the terms of the Apache license 2.0 license.

If you publish any results with data collected using this software, please cite the following paper:

**Classification of Encrypted IoT Traffic Despite Padding and Shaping.** Aviv Engelberg, Avishai Wool. [arXiv Preprint](https://arxiv.org/abs/2110.11188)

If you have any questions or suggestions for improvements, please let me know.
<p>&nbsp;</p>

We examined a wide range of smart devices from different classes (cameras, plugs, bulbs, etc.) coming from well-known vendors (e.g. Amazon, Belkin, etc).

The devices' traffic traces are from the open sources of [Sivanathan et al.](https://ieeexplore.ieee.org/document/8116438) and [Trimananda et al.](https://www.ndss-symposium.org/ndss-paper/packet-level-signatures-for-smart-home-devices/). 

You may use different traffic traces from other sources, but please make sure to follow the usage instructions below.
<p>&nbsp;</p>

The developed software is intended to examine padding and shaping mitigations applied on a real-time tested network traffic and demonstrate how we could learn and simulate traffic similarly ourselves in order to gain information about the tested network.

This work was developed for research purposes only, do not try to use it for malicious purposes. 
## Usage Instructions

To execute the code run
```
python classifier_IoT.py [action=None][directoryName=None]
```
The argument action specifies the desired action that you want to apply on the traffic. Its value should be an integer between 0-8. 
The argument directoryName should only be specified if you choose the value 0 for action. It specifies the directory's name in which the simulation file will be saved.

Always run the code from the same working directory as it depends on directories it creates and reads from during its execution.

## First Run
When you execute the program for the first time run it without arguments
```
python classifier_IoT.py 
```
This will create the following directories in your working directory:

1. "Saved Simulations": Directory where all the simulations files created during execution are saved.
2. "Upload Simulations": Directory from which simulations file are uploaded and used for the program's purpose.
3. "SavedSimulations\Subsets": Sub-directory inside "SavedSimulations" in which devices' subsets' simulation files are saved.
4. "Tested Traffic": Directory in which tested traffic traces are stored.

## After your first run
Make sure to create a directory for each candidate device in your network inside the working directory.

Inside each device's directory put its learning traffic trace (either a ".pcap" or a ".pcapang" file), i.e., trace related to the device's outbound traffic. 

Inside the "Tested Traffic" directory put the tested traffic traces.

**Make sure that all of the above traces have unique names, as the program use them as identifiers for the simulations.**
## Creating Simulation Files

After you did this, you would need to execute
```
python classifier_IoT.py 0 yourSavedDirectoryName
```
This will create the sub-directory directoryName inside the "Saved Simulations" directory. 

It would then create a simulation file for any learning and test trace file and save it inside this sub-directory. 

Simulation files contain data related to the devices' outbound traffic after applying the padding and shaping on it.

Simulations related to learning traces (aka **learnt simulations**) will help us classify the tested traffic, and those related to tested traces (aka **tested simulations**) will imitate real-time tested traffic protected with padding and shaping that we would like to examine and classify.

Since our program is only meant to simulate and imitate real padded and shaped traffic and not create actual ".pcap" files after applying these mitigations, we also simulate the tested traces ourselves and then save them obfuscated in their tested simulation files.

The default values for simulations are **q=0.1,W=80**. You can modify their values (**W** has to be either a positive integer -for **Random-Padding**, or the negative integer (-100) - for **Level-100 Padding**, **q** needs to be a real number between 0 to 1) in DoSimulations function in line 636, in order to simulate the devices with different values than the default values **q=0.1,W=80**.
<p>&nbsp;</p>

Each simulation contains the following fields:
1. <ins>frequencies</ins>: A dictionary that has packet sizes as keys and their associated frequencies as values.
2. <ins>realPeriods</ins>: For learning trace it contains the device's real-traffic periods; for tested trace (because we want to obfuscate it) it stores all the device's periods
3. <ins>fakePeriods</ins>: For learning trace it contains the device's only-cover-traffic periods; for tested trace it's an empty list
4. <ins>deviceNumber</ins>: For learning trace it stores the device's number, for tested trace (unknown device) it stores arbitrarily (-1)
5. <ins>isLearntSimulation</ins>: For learning trace it is **True**, for tested trace it is **False**
6. <ins>file</ins>: The name of the learning/test trace file 
7. <ins>q</ins>: For learning trace it stores the value of **q** used in the simulation, for tested trace (because we want to obfuscate it) it stores arbitrarily (-1)
8. <ins>W</ins>: For learning trace it stores the value of **W** used in the simulation, for tested trace (because we want to obfuscate it) it stores arbitrarily (-1)

## Other Actions Explanation

### Notes: 
1. The second argument directoryName is not required for action!=0.
2. Use identical duration time for every tested trace. For the recommended duration times of the traces, refer to [arXiv Preprint](https://arxiv.org/abs/2110.11188).
3. The actions below demonstrate how information about tested traffic can be inferred through simple analysis, but are not guaranteed to yield optimal results. You may add your own modifications, to make this program more suitable for the datasets you choose to use- e.g. taking thresholds different from the mid-points between averages, different value of **k** for the **KNN** algorithm, etc.
4. For **action=2, 3, 4, 5 or 8**, make sure that all the learnt simulations were simulated using the same values for **q&W**, and that those values are as closest as possible to the values of **q&W** in the tested simulations.

### action=1: Merging several Tested Simulations of devices into Tested Simulation of the devices' subset
Assumption: Before running this make sure to put inside the directory "Upload Simulations" at least one tested simulation - each of a different device- where all of them were simulated using the same values for **q&W**. Action: Saving inside sub-directory "Subsets" in "Saved Simulations" a tested simulation file for the subset of devices in the tested simulations.

### action=2: Classifying devices
Assumptions: Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device, and at least one tested simulation of a device. Action: Based on the learnt simulations, printing to stdout the classification of which device is active in every tested simulation file.

### action=3: Computing thresholds for estimating number of active devices  
Assumptions: Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device, simulated from one learning trace for each device, whose duration times are identical to those of the tested traces. Action: Compute the thresholds for estimating the number of active devices and write it into a file "ThresholdsPacketRates.txt" in the working directory.

### action=4: Subset Identification - Using Full Comparison Check
Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device, and at least one tested simulation of a subset of devices. 

Based on the learnt simulations, printing to stdout the estimated subset of active devices in every tested simulation file - using the Full Comparison Check algorithm (for mor information - see [arXiv Preprint](https://arxiv.org/abs/2110.11188)).

### action=5: Subset Identification - Using Fast Scores Bsed Check(FSBC)
Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device, and at least one tested simulation of a subset of devices. 

Based on the learnt simulations, printing to stdout the estimated subset of active devices in every tested simulation file - using the FSBC algorithm (for mor information - see [arXiv Preprint](https://arxiv.org/abs/2110.11188)).

### action=6: Estimating value of W 
Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device per each value of **W** you are examining, and at least one tested simulation of a device.

Based on all the learnt simulations, printing to stdout the estimated value of **W** chosen from all the examined values of **W** in the learnt simulations along with the classification of which device is active - for every tested simulation file.

### action=7: Estimating value of q 
Before running this, first execute the program with action=1 (if the value of **W** is unknown then with action=5 instead) in order to get the tested device in each tested simulation. Then make sure to put inside the directory "Upload Simulations" all the tested simulation whose active device is identical, and one learnt simulation of that device per each value of **q** you are examining.

Based on all the learnt simulations, printing to stdout the estimated value of **q** chosen from all the examined values of **q** in the learnt simulations for every tested simulation file.

### action=8: Classifying Periods: Real/Only-Cover Traffic
Before running this make sure to put inside the directory "Upload Simulations" one learnt simulation of each device, and at least one tested simulation of a device.

Based on the learnt simulations, printing to stdout the classification (using KNN) report of the periods ("Real Traffic"/"Only-Cover Traffic") in every tested simulation file.








