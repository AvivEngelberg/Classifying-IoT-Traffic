# smart-home
This project is licensed under the terms of the Apache license 2.0 license.

If you publish any results with data collected using this software, please cite the following paper:

**Classification of Encrypted IoT Traffic Despite Padding and Shaping.** Aviv Engelberg, Avishai Wool. [arXiv Preprint](https://arxiv.org/abs/2110.11188)

We examined a wide range of smart devices from diffeernt classes (cameras, plugs, bulbs, etc.) coming from well known vendors (e.g. Amazon, Belkin, etc).
The devices' traffic traces are from the open sources of [Sivanathan et al.](https://ieeexplore.ieee.org/document/8116438) and [Trimananda et al.](https://www.ndss-symposium.org/ndss-paper/packet-level-signatures-for-smart-home-devices/). 
You may use different traffic traces from other sources, but please make sure to follow the usage instructions below.
The developed software is intended to examine padding and shaping applied on a tested network traffic and demonstrate how we could learn and simulate it similarly ourselves in order to gain information about the tested network.
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
Inside the "Tested Traffic" dorectory put the tested traffic






