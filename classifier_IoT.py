import os
import sys
import ast
import random
import numpy as np
import itertools
import  scipy.spatial.distance 
import sklearn
import collections
import operator
import statistics
from scapy.all import *
from os import listdir
from os.path import isfile, join
from itertools import combinations
from heapq import nlargest 
from operator import itemgetter
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
R=100
T=1
default_W=80
default_q=0.1
sizeList=[]
timeList=[]
dictPackets={}
previousEpochTime=0
currentEpochTime=0
currentTimeSinceFirstFrame=0 
savedSimulationsDir="Saved Simulations"
uploadSimulationsDir="Upload Simulations"
testedTrafficDir="Tested Traffic"

def MethodFilter(pkt):
    global sizeList,timeList,dictPackets
    global previousEpochTime,currentEpochTime,currentTimeSinceFirstFrame
    
    #First packet
    if previousEpochTime==0:
        previousEpochTime=pkt.time
    #Other packets
    else:
        currentEpochTime=pkt.time
        currentTimeSinceFirstFrame+=float(currentEpochTime-previousEpochTime)
        previousEpochTime=currentEpochTime
    sizeList+=[len(pkt)]    
    timeList+=[currentTimeSinceFirstFrame]
    dictPackets[currentTimeSinceFirstFrame]=len(pkt)    

def Extractor(file):
    global sizeList,timeList,dictPackets
    global previousEpochTime,currentEpochTime,currentTimeSinceFirstFrame
    sizeList=[]
    timeList=[]
    dictPackets={}
    previousEpochTime=0
    currentEpochTime=0
    currentTimeSinceFirstFrame=0
    sniff(offline=file,prn=MethodFilter,store=0)
    return sizeList,timeList,dictPackets
    
    
def Padding(pktSize,W):
    randint=random.randint
    #Random Padding
    if W>0:
        return pktSize+randint(1,W)
    #Level-100 Padding
    if W==-100:
        if pktSize<=100:
            return 100
        elif pktSize<=200:
            return 200
        elif pktSize<=300:
            return 300
        elif pktSize<999:
            return randint(pktSize,1000)
        elif pktSize<=1399:
            return randint(pktSize,1400)
        else:
            return 1500
    

def STP(timeList,sizeList,dictPackets,q,W):
    Counter=collections.Counter
    sort=np.sort
    binomial=np.random.binomial
    randint=random.randint
    choices=random.choices
    uniform=random.uniform
    
    updatedCurrentTime=0
    injectStart=0
    injectEnd=0
    #T*R pkts in T sec so this is the inter-packet time
    timeStep=T/(T*R-1)
    packetSizesAfterSTP=[]
    realPeriods=[]
    fakePeriods=[]
    #This will help us sampling from the device's packet-sizes distribution
    frequencies=Counter(sizeList)
    packetSizesList=list(frequencies.keys())
    frequenciesList=[frequencies[p] for p in packetSizesList]
        
    t=0
    finishTime=timeList[-1]
    while t<=finishTime:
        #Injecting a period w.p. q
        if t%T==0 and binomial(1,q):
            injectOffset=uniform(0,T)
            if t+injectOffset>injectEnd:
                injectStart=t+injectOffset
                injectEnd=injectStart+T
            else:
                injectEnd=injectEnd+T   
        #After injecting a period, need to incremnt t to be right after the period               
        if updatedCurrentTime>0:
            t=updatedCurrentTime
            updatedCurrentTime=0            
            
        if t>=injectStart and t<=injectEnd:
            #Checking if there're times indicating real activities of the device from current time t to injectEnd: If yes- a real-period,o.w. an only-cover-period
            if len([z for z in timeList if z>=t and z<=injectEnd ])>0:
                #queueRealPackets is a sorted queue of real-packets' times 
                queueRealPackets=[]
                currentPeriod=[]
                #Checking if there's real-packet at time t 
                if t in timeList: 
                    queueRealPackets+=[t]
                for i in range(T*R):
                    #If we exceeded the finishTime, fill with zeroes the currentPeriod and break from the loop
                    if t+i*timeStep>finishTime:
                        currentPeriod+=[0 for k in range(T*R-len(currentPeriod))]
                        break
                    #Adding the real-packets (if exist) in the current step in the period
                    queueRealPackets+=list(sort([z for z in timeList if i>0 and z<=t+i*timeStep and z>t+(i-1)*timeStep]))
                    #Emitting a padded real-packet
                    if len(queueRealPackets)>0:
                        #First packet in queueRealPackets has highest priority
                        realSize=dictPackets[queueRealPackets[0]]
                        paddedSize=Padding(realSize,W)
                        currentPeriod+=[paddedSize]
                        #Remove first packet from the queue
                        queueRealPackets=queueRealPackets[1:]
                    #Emitting a padded cover-packet
                    else:
                        #Sampling packet-size from the device's distribution
                        coverPacketSize=choices(packetSizesList,frequenciesList)[0]
                        paddedSize=Padding(coverPacketSize,W)
                        currentPeriod+=[paddedSize]
                packetSizesAfterSTP+=currentPeriod
                realPeriods+=[currentPeriod]
            else:
                currentPeriod=[]
                for i in range(T*R):
                    #If we exceeded the finishTime, fill with zeroes the currentPeriod and break from the loop
                    if t+i*timeStep>finishTime:
                        currentPeriod+=[0 for k in range(T*R-len(currentPeriod))]
                        break
                    #Sampling packet-size from the device's distribution
                    coverPacketSize=choices(packetSizesList,frequenciesList)[0]
                    paddedSize=Padding(coverPacketSize,W)
                    currentPeriod+=[paddedSize]
                packetSizesAfterSTP+=currentPeriod
                fakePeriods+=[currentPeriod]
                
            """
            Incrementing t to the next closest time in which t%T==0 so we'll make the period-injection 
            decision w.p. q, want to incremnt later t to be updatedCurrentTime (right after the period) 
            """
            updatedCurrentTime=t+T
            t=t+T-t%T
        #Checking if there're times indicating real activities of the device from current time t to injectEnd: If yes- a real-period
        elif len([z for z in timeList if z>=t and z<=t+timeStep ])>0:
            injectStart=t
            injectEnd=injectStart+T
            #queueRealPackets is a sorted queue of real-packets' times 
            queueRealPackets=[]
            currentPeriod=[]
            #Checking if there's real-packet at time t 
            if t in timeList:
                queueRealPackets+=[t]
            for i in range(T*R):
                #If we exceeded the finishTime, fill with zeroes the currentPeriod and break from the loop
                if t+i*timeStep>finishTime:
                    currentPeriod+=[0 for k in range(T*R-len(currentPeriod))]
                    break
                #Adding the real-packets (if exist) in the current step in the period
                queueRealPackets+=list(sort([z for z in timeList if i>0 and z<=t+i*timeStep and z>t+(i-1)*timeStep]))
                #Emitting a padded real-packet
                if len(queueRealPackets)>0:
                    #First packet in queueRealPackets has highest priority
                    realSize=dictPackets[queueRealPackets[0]]
                    paddedSize=Padding(realSize,W)
                    currentPeriod+=[paddedSize]
                    #Remove first packet from the queue
                    queueRealPackets=queueRealPackets[1:]
                #Emitting a padded cover-packet
                else:
                    #Sampling packet-size from the device's distribution
                    coverPacketSize=choices(packetSizesList,frequenciesList)[0]
                    paddedSize=Padding(coverPacketSize,W)
                    currentPeriod+=[paddedSize]
            packetSizesAfterSTP+=currentPeriod
            realPeriods+=[currentPeriod]    
            """
            Incrementing t to the next closest time in which t%T==0 so we'll make the period-injection 
            decision w.p. q, want to incremnt later t to be updatedCurrentTime (right after the period) 
            """
            updatedCurrentTime=t+T
            t=t+T-t%T
        #Otherwise, increment t to the next time step
        else:
            t+=timeStep
    
    return packetSizesAfterSTP,realPeriods,fakePeriods


def CreateSubsetSimulation(testedSimulations):
    Counter=collections.Counter
    totalFrequencies=Counter()
    totalPeriods=[]
    totalFile=""
    #Merging the tested frequencies, periods and files' names of any Tested Simulation
    for simulation in testedSimulations:             
        totalFrequencies+=simulation[0]
        totalPeriods+=simulation[1]
        #Last character ('\n') is removed
        totalFile+=simulation[5][:-1]
    #q&W are assumed to be the same for any Tested Simulation, arbitrarily taken from the first simulation
    q=testedSimulations[0][6]
    W=testedSimulations[0][7]
    #Creating Simulation for the subset of devices in testedSimulations
    currentSimulation =(dict(totalFrequencies),totalPeriods,[],-1,False,totalFile,q,W)
    simulationFile="Simulation_"+totalFile+".txt"        

    directoryName=join(savedSimulationsDir,"Subsets")
    if os.path.exists(join(directoryName, simulationFile)):
        os.remove(join(directoryName, simulationFile))

    f=open(join(directoryName, simulationFile),'a')
    
    for i in range(len(currentSimulation)):
        f.write(str(currentSimulation[i])+"\n")
    f.close()    



def ClassifyingDevices(learntSimulations,testedSimulations,numberOfDevices):
    cosine=scipy.spatial.distance.cosine
    norm = np.linalg.norm
    learntFrequenciesList=[]
    for simulation in learntSimulations:           
        learntFrequencies=simulation[0]
        learntFrequenciesList+=[learntFrequencies]
        
    testedDevices={}
    #Classifying Tested Simulations
    for simulation in testedSimulations:             
        testedFrequencies=simulation[0]
        cosineResults=[]
        for deviceNumber in range(1,numberOfDevices+1):
            learntFrequencies=learntFrequenciesList[deviceNumber-1]
            #Common sizes bins
            bins=list(set(list(learntFrequencies.keys())+list(testedFrequencies.keys())))
            learntVector=[learntFrequencies[x] if x in learntFrequencies  else 0 for x in bins]
            testedVector=[testedFrequencies[x] if x in testedFrequencies  else 0 for x in bins]

            learntVector=learntVector/norm(learntVector)
            testedVector=testedVector/norm(testedVector)
            cosineResults+=[cosine(learntVector,testedVector)]         
        testedDevice=np.argmin(cosineResults)+1
        testedDevices[simulation[5]]=testedDevice
        print("The Device in Tested Simulation",simulation[5],"is",testedDevice)
    return testedDevices

def SaveThresholds(learntSimulations,numberOfDevices):
    mean=np.mean
    totalSumOfAll=[]
    for deviceNumber in range(1,numberOfDevices+1):
        sizeList=[]
        simulation=learntSimulations[deviceNumber-1]              
        learntFrequencies=simulation[0]
        totalSumOfAll+=[sum(learntFrequencies.values())]
    #Adding first the average packet rate for one active device
    averagePacketRate=[mean(totalSumOfAll)]
    #Average packet rate for i devices is exactly the average for one device multiplied by i (easy to prove) 
    for i in range(2,numberOfDevices+1): 
        averagePacketRate+=[i*averagePacketRate[0]]

    thresholdsPacketRate=[]
    for i in range(len(averagePacketRate)-1):
        thresholdsPacketRate+=[(averagePacketRate[i]+averagePacketRate[i+1])/2]
        
    file="ThresholdsPacketRates.txt"
    if os.path.exists(file):
        os.remove(file)
    f=open(file,'a')
    f.write(str(thresholdsPacketRate))
def EstimateNumberOfDevices(testedFrequencies):
    file="ThresholdsPacketRates.txt"
    f=open(file,'r')
    linesOfFile=f.readlines()
    thresholdsPacketRate=ast.literal_eval(linesOfFile[0])
    f.close()
    
    packetRate=sum(testedFrequencies.values())
    #Default estimated number is len(thresholdsPacketRate)+1=numberOfDevices
    estimatedNumber=len(thresholdsPacketRate)+1
    for i in range(len(thresholdsPacketRate)):
        if packetRate<thresholdsPacketRate[i]:
            estimatedNumber=i+1
            break 
    return estimatedNumber

def FullComparisonCheck(learntSimulations,testedSimulations,numberOfDevices):
    norm = np.linalg.norm
    Counter=collections.Counter  
    cosine=scipy.spatial.distance.cosine    
    learntFrequenciesList=[]
    allCombinationsLearntFrequencies={}
   
    estimatedNumbers={}
    possibleSubsetsSizes=[]
    #We save in advance the estinated number of devices for each Tested Simulation
    for simulation in testedSimulations:            
        testedFrequencies=simulation[0]
        estimatedNumber=EstimateNumberOfDevices(testedFrequencies)  
        estimatedNumbers[simulation[5]]=estimatedNumber
        #We only need need to check subsets' sizez at most off by 1 than the estimated size
        possibleSubsetsSizes+=[estimatedNumber,estimatedNumber+1]
        if estimatedNumber>1:
            possibleSubsetsSizes+=[estimatedNumber-1]
    possibleSubsetsSizes=list(set(possibleSubsetsSizes))
    
    for deviceNumber in range(1,numberOfDevices+1):         
        simulation=learntSimulations[deviceNumber-1]            
        learntFrequencies=simulation[0]
        learntFrequenciesList+=[learntFrequencies]
        
    #Learning only the necessary possible sizes
    for k in possibleSubsetsSizes:
        for learntCombination in list(combinations(range(1,numberOfDevices+1),k)):
            learntFrequencies=Counter()
            for deviceNumber in learntCombination:
                learntFrequencies+=learntFrequenciesList[deviceNumber-1]
            allCombinationsLearntFrequencies[learntCombination]=learntFrequencies

    for simulation in testedSimulations:            
        testedFrequencies=simulation[0]        
        estimatedNumber=estimatedNumbers[simulation[5]]
        minVal=1
        bestCombination=[]
        for learntCombination in allCombinationsLearntFrequencies:#1-10
            #We only need need to check subsets' sizez at most off by 1 than the estimated size
            if len(learntCombination)>estimatedNumber+1 or len(learntCombination)<estimatedNumber-1 :
                continue
            
            learntFrequencies=allCombinationsLearntFrequencies[learntCombination]
            #Common sizes bins    
            bins=list(set(list(learntFrequencies.keys())+list(testedFrequencies.keys())))
            learntVector=[learntFrequencies[x] if x in learntFrequencies  else 0 for x in bins]
            testedVector=[testedFrequencies[x] if x in testedFrequencies  else 0 for x in bins]
            
            learntVector=learntVector/norm(learntVector)
            testedVector=testedVector/norm(testedVector)
            currentCosine=cosine(learntVector,testedVector)
            if currentCosine<minVal:
                minVal=currentCosine
                bestCombination=learntCombination
        print("The Active Subset in Tested Simulation",simulation[5],"is",bestCombination) 

def FSBC(learntSimulations,testedSimulations,numberOfDevices):          
    ceil=np.ceil
    sort=np.sort
    Counter=collections.Counter
    f1=0.8
    f2=0.9
    learntFrequenciesList=[]
    commonSizesDevices=[]
    devicesTopUnique=[]
    for deviceNumber in range(1,numberOfDevices+1):         
        simulation=learntSimulations[deviceNumber-1]             
        learntFrequencies=simulation[0]
        learntFrequenciesList+=[learntFrequencies]                  
        commonSizesDevices+=[learntFrequencies.most_common(int(ceil(f1*len(learntFrequencies))))]
        
    for deviceNumber in range(1,numberOfDevices+1):
        currentLearntFrequencies=learntFrequenciesList[deviceNumber-1]
        #Merging other devices's packet sizes into one list
        otherDevicesSizes=list(itertools.chain.from_iterable([list(learntFrequenciesList[k-1].keys()) for k in range(1,numberOfDevices+1) if k!=deviceNumber]))
        #All the unique packet sizes in the current device that other devices don't have
        currentDeviceUniques=list(np.setdiff1d(list(currentLearntFrequencies.keys()),otherDevicesSizes))    
        currentDeviceUniquesDict={s:currentLearntFrequencies[s] for s in currentDeviceUniques}
        #If the current device has unique packet sizes we wake its top-unique, otherwise arbitrarily (-1)
        devicesTopUnique+=[Counter(currentDeviceUniquesDict).most_common(1)[0][0] if len(currentDeviceUniquesDict)>0 else -1]
        
    for simulation in testedSimulations:             
        testedFrequencies=simulation[0]
        estimatedNumber=EstimateNumberOfDevices(testedFrequencies)               
        scoresList=[]
        for deviceNumber in range(1,numberOfDevices+1):
            currentDeviceFrequencies=learntFrequenciesList[deviceNumber-1]
            commonSizes=commonSizesDevices[deviceNumber-1]
            topUnique=devicesTopUnique[deviceNumber-1]
            total=len(commonSizes)
            score=1
            if topUnique!=-1:
                total+=1
                if topUnique not in testedFrequencies:
                    score-=1/total       
            for currentSize in commonSizes:
                #currentSize is a tuple where currentSize[0]- packet size and currentSize[1]- its frequency
                if currentSize[0] not in testedFrequencies or testedFrequencies[currentSize[0]]<f2*currentSize[1]:
                    score-=1/total
            scoresList+=[score]
        #Taking highest scores devices as the estimated subset
        nLargestList=nlargest(estimatedNumber, range(len(scoresList)), key=lambda x: scoresList[x])
        estimatedCombination=sort([x+1 for x in nLargestList])
        print("The Active Subset in Tested Simulation",simulation[5],"is",tuple(estimatedCombination))

def EstimatingW(learntSimulations,testedSimulations,numberOfDevices):
    cosine=scipy.spatial.distance.cosine
    norm = np.linalg.norm  
    learntFrequenciesListAllModeledW={}
    separateByModeledW = {}
    for simulation in learntSimulations:
        separateByModeledW.setdefault(simulation[7], []).append(simulation)
    learntSimulationsAllModeledW=list(separateByModeledW.values())
    
    #Each learntSimulationsModeledW is a list of simulations with the same value of W
    for learntSimulationsModeledW in learntSimulationsAllModeledW:
        learntFrequenciesList=[]
        #modeledW is same for any simulation in learntSimulationsModeledW, arbitrarily taken from the first simulation
        modeledW=learntSimulationsModeledW[0][7]
        #Sort by deviceNumber 
        learntSimulationsModeledW=sorted(learntSimulationsModeledW, key=itemgetter(3))     
        for deviceNumber in range(1,numberOfDevices+1):         
            simulation=learntSimulationsModeledW[deviceNumber-1]             
            learntFrequencies=simulation[0]
            learntFrequenciesList+=[learntFrequencies]
        learntFrequenciesListAllModeledW[modeledW]=learntFrequenciesList
               
    for simulation in testedSimulations:           
        testedFrequencies=simulation[0]  
        bestW=0
        minVal=1
        bestDevice=0
        for modeledW in learntFrequenciesListAllModeledW:
            cosineResults=[]
            for deviceNumber in range(1,numberOfDevices+1):
                learntFrequencies=learntFrequenciesListAllModeledW[modeledW][deviceNumber-1]
                #Common sizes bins
                bins=list(set(list(learntFrequencies.keys())+list(testedFrequencies.keys())))
                learntVector=[learntFrequencies[x] if x in learntFrequencies  else 0 for x in bins]
                testedVector=[testedFrequencies[x] if x in testedFrequencies  else 0 for x in bins]

                learntVector=learntVector/norm(learntVector)
                testedVector=testedVector/norm(testedVector)
                cosineResults+=[cosine(learntVector,testedVector)]      
            if min(cosineResults)<minVal:
                minVal=min(cosineResults)
                bestDevice=np.argmin(cosineResults)+1
                bestW=modeledW
                
        print("The Device in Tested Simulation",simulation[5],"is",bestDevice)
        print("The Estimated W in Tested Simulation",simulation[5],"is",bestW)

def EstimatingQ(learntSimulations,testedSimulations,numberOfDevices):
    #Sort by q 
    learntSimulations=sorted(learntSimulations, key=itemgetter(6))       
    packetRates=[]
    for i in range(len(learntSimulations)):
        simulation=learntSimulations[i]            
        learntDeviceFrequencies=simulation[0]
        packetRates+=[(sum(learntDeviceFrequencies.values()),simulation[6])]  
    #Computing the thresholds based on the packet rates for any learnt value of q
    thresholdsPacketRate=[]
    for i in range(len(packetRates)-1):
        thresholdsPacketRate+=[(packetRates[i][0]+packetRates[i+1][0])/2]
    
    for simulation in testedSimulations:           
        testedFrequencies=simulation[0]       
        testedPacketRate=sum(testedFrequencies.values())
        #Default estimatedQ - largest value learnt of q
        estimatedQ=packetRates[-1][1]  
        for i in range(len(thresholdsPacketRate)):
            if testedPacketRate<thresholdsPacketRate[i]:
                estimatedQ=packetRates[i][1]
                break
        print("The Estimated q in Tested Simulation",simulation[5],"is",estimatedQ)

def ClassifyingPeriods(learntSimulations,testedSimulations,numberOfDevices):
    cosine=scipy.spatial.distance.cosine
    #Redirect stdout's output to devnull, because we only want the returned value of ClassifyingDevices function without any printing to stdout
    f = open(os.devnull, 'w')
    originalStdout=sys.stdout
    sys.stdout = f
    #Getting the tested device for any Tested Simulation
    testedDevices=ClassifyingDevices(learntSimulations,testedSimulations,numberOfDevices)
    #Restore stdout value, so we'll be able to print to stdout later
    sys.stdout=originalStdout
    
    for simulation in testedSimulations:
        testedDevice=testedDevices[simulation[5]]
        simulation=learntSimulations[testedDevice-1]
        
        #Building the training set of periods from the same device's learnt periods
        learntRealPeriods=simulation[1]
        learntFakePeriods=simulation[2]    
        train_periods=learntFakePeriods+learntRealPeriods
        scaler = StandardScaler()   
        train_periods = scaler.fit_transform(train_periods)        
        label_periods=[0]*len(learntFakePeriods)+[1]*len(learntRealPeriods)    
                 
        k=119
        classifier = KNeighborsClassifier(n_neighbors=k,metric=cosine)
        classifier.fit(train_periods, label_periods)
    
        #Classifying the device's tested periods
        testedPeriods=simulation[1]
        testedPeriods = scaler.transform(testedPeriods)
        y_pred = classifier.predict(testedPeriods)
        classificationPeriods=[("Period"+str(i+1),"Real Traffic" if y_pred[i]==1 else "Only-Cover Traffic") for i in range(len(y_pred))]
        print("The Periods' Classification in Tested Simulation",simulation[5],"is",classificationPeriods)

def DoAction(simulations,action,numberOfDevices):
    learntSimulations=[x for x in simulations if x[4]==True]
    testedSimulations=[x for x in simulations if x[4]==False]
    #Sort by deviceNumber
    learntSimulations=sorted(learntSimulations, key=itemgetter(3))

    #Merging several Tested Simulations of devices into Tested Simulation of the devices' subset
    if action==1:
        CreateSubsetSimulation(testedSimulations)

    #Classifying dominating active devices/Local adversary
    if action==2:    
        ClassifyingDevices(learntSimulations,testedSimulations,numberOfDevices)
    #Save Thresholds for Estimating Number of Active devices      
    if action==3:    
        SaveThresholds(learntSimulations,numberOfDevices)
    #Subset Identification - Full Comparison Check
    if action==4:
        FullComparisonCheck(learntSimulations,testedSimulations,numberOfDevices)  
    #Subset Identification - FSBC
    if action==5:
        FSBC(learntSimulations,testedSimulations,numberOfDevices) 
    #Estimating value of W 
    if action==6:
        EstimatingW(learntSimulations,testedSimulations,numberOfDevices)
    #Estimating value of q                 
    if action==7:
        EstimatingQ(learntSimulations,testedSimulations,numberOfDevices)  
    #Classifying Periods: Real/Only-Cover Traffic
    if action==8:
        ClassifyingPeriods(learntSimulations,testedSimulations,numberOfDevices)          

def SplitPeriods(lst):
    for i in range(0, len(lst), T*R):
        yield lst[i:i + T*R]

def UploadSimulations():
    Counter=collections.Counter    
    simulations=[]
    simulationFiles=[join(uploadSimulationsDir, x) for x in listdir(uploadSimulationsDir) if isfile(join(uploadSimulationsDir, x)) and (x.endswith("txt"))]
    
    for currentSimulation in simulationFiles: 
        f=open(currentSimulation,'r')
        linesOfFile=f.readlines()
        frequencies=Counter(ast.literal_eval(linesOfFile[0]))
        realPeriods=ast.literal_eval(linesOfFile[1])
        fakePeriods=ast.literal_eval(linesOfFile[2])
        deviceNumber=ast.literal_eval(linesOfFile[3])
        isLearntSimulation=ast.literal_eval(linesOfFile[4])
        file=linesOfFile[5]
        q=ast.literal_eval(linesOfFile[6])
        W=ast.literal_eval(linesOfFile[7])
        
        simulations+=[[frequencies,realPeriods,fakePeriods,deviceNumber,isLearntSimulation,file,q,W]]
        f.close()
    return simulations
        
def ObfuscatedSTP(timeList,sizeList,dictPackets,q,W):
    return STP(timeList,sizeList,dictPackets,q,W)[0]
    
def SaveSimulations(devicesData,q,W,directoryName):
    Counter=collections.Counter
    for (file,sizeList,timeList,dictPackets,deviceNumber,isLearntSimulation) in devicesData:
        if isLearntSimulation:
            packetSizesAfterSTP,realPeriods,fakePeriods=STP(timeList,sizeList,dictPackets,q,W) 
            currentSimulation=(dict(Counter(packetSizesAfterSTP)),realPeriods,fakePeriods,deviceNumber,isLearntSimulation,file,q,W)
        #Tested Simulation
        else:         
            #This is imitating the obfuscatd output that we would observe of tested traffic
            packetSizesAfterSTP=ObfuscatedSTP(timeList,sizeList,dictPackets,q,W)           
            fakePeriods=[]
            #All of the Tested Simulation's periods are stored by default in its realPeriods  
            realPeriods=list(SplitPeriods(packetSizesAfterSTP))
            #We also obufuscted values of q&W arbitrarily to (-1)
            currentSimulation=(dict(Counter(packetSizesAfterSTP)),realPeriods,fakePeriods,deviceNumber,isLearntSimulation,file,-1,-1)    
       
        simulationFile="Simulation_"+file+"_W"+str(W)+"q"+str(q)+".txt"    
        if os.path.exists(join(directoryName, simulationFile)):
            os.remove(join(directoryName, simulationFile))
        f=open(join(directoryName, simulationFile),'a')    
        
        #Saving data to simulation file  
        for i in range(len(currentSimulation)):
            f.write(str(currentSimulation[i])+"\n")
        f.close()

def DoSimulations(devicesData,action,numberOfDevices,direcoryName=None):
    #Can modify their values to simulate traffic with different values of q&W. For Level-100 padding, specify W=-100
    q=default_q 
    W=-700#default_W
    if action!=0:
        simulations=UploadSimulations()
        DoAction(simulations,action,numberOfDevices)
    else:
        SaveSimulations(devicesData,q,W,direcoryName)

def main(argv):
    #First Execution
    if len(argv)==1:
        dirNames=[savedSimulationsDir]
        dirNames+=[uploadSimulationsDir]
        dirNames+=[testedTrafficDir]
        dirNames+=[join(savedSimulationsDir,"Subsets")]      
        for dirName in dirNames:
            if not os.path.exists(dirName):
                os.makedirs(dirName)
    else:       
        action=int(argv[1])    
        #Number of candidate devices in the network is assumed to be the number of dirs in the working dir who starts with "device"      
        numberOfDevices=len([x for x in listdir() if not isfile(x) and x.startswith("device")])
        devicesData=[]

        if action!=0:
            DoSimulations(devicesData,action,numberOfDevices)
        else:     
            if len(argv)>2:
                direcoryName=join(savedSimulationsDir,argv[2])
                if not os.path.exists(direcoryName):
                    os.makedirs(direcoryName)       
                for deviceNumber in range(1,numberOfDevices+1):
                    deviceDir="device"+str(deviceNumber)
                    trafficTraceFiles=[x for x in listdir(deviceDir) if isfile(join(deviceDir, x)) and (x.endswith("pcap") or x.endswith("pcapng"))]
                    isLearntSimulation=True
         
                    for file in trafficTraceFiles:
                        sizesList,timesList,dictPackets=Extractor(join(deviceDir, file))
                        devicesData+=[(deviceDir+"_"+file,sizeList,timeList,dictPackets,deviceNumber,isLearntSimulation)]
                  
                testedFiles=[x for x in listdir(testedTrafficDir) if isfile(join(testedTrafficDir, x)) and (x.endswith("pcap") or x.endswith("pcapng"))]
                isLearntSimulation=False
                #Indicating unknown device
                deviceNumber=-1
                for file in testedFiles:
                    sizesList,timesList,dictPackets=Extractor(join(testedTrafficDir, file))           
                    devicesData+=[(testedTrafficDir+"_"+file,sizeList,timeList,dictPackets,deviceNumber,isLearntSimulation)]
                DoSimulations(devicesData,action,numberOfDevices,direcoryName)
            else:
                print("Please specify directoryName argument in case of action=0")
                
if __name__ == '__main__':
    main(sys.argv)
