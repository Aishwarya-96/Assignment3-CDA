# -*- coding: utf-8 -*-
"""
Created on Sun Jun 24 16:15:07 2018

@author: Aishwarya
"""

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import OneHotEncoder
from sklearn.cross_validation import train_test_split
from sklearn.metrics import confusion_matrix, precision_recall_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from matplotlib import pyplot as plt

file_name = 'capture20110818.pcap.netflow.csv'
L = 10 # taking top L n-grams into account
w = 40 #length of sliding window
n = 7 # the number of n-gram
df = pd.read_csv("capture20110818.pcap.netflow.csv")
#df.head()
df['date_time'] = pd.to_datetime(df[['Dateflow', 'start']].apply(lambda x: ' '.join(x), axis=1))

# Assign simple labels
def assgin_label(label):
    if label.find('Normal')!=-1:
        return 0
    elif label.find('Botnet')!=-1:
        return 1 
    else:
        return -1
df['label'] = df['Label'].apply(lambda x: assgin_label(x))

# imbalanced: 184987 botnet, 29893 normal
new_df = df[df['label']!=-1]

data=new_df[['Durat','Prot','Packets','Bytes']]

name_prot = df.Prot.unique()
name_prot_dict = {name:i for i,name in enumerate(name_prot)}
##  Obtaining Timed Events ##
#def change_Dir(x):
#    return name_dir_dict[x]
def change_Prot(x):
    return name_prot_dict[x]

data['Prot'] = data['Prot'].apply(lambda x: change_Prot(x))
data['timestamp'] = new_df.date_time
data['IP'] = new_df.Src_Addr
def get_percentile(p_list,name):
    split_list = []
    for p in p_list:
        split_list.append(np.percentile(new_df[name],p))
    return split_list

def assign_value(x,split_list):
    for i,s in enumerate(split_list):
        if x<s:
            return i
    return len(split_list)

split_list_Dur = get_percentile([25,50,75],'Durat')
data['Durat'] = new_df['Durat'].apply(lambda x: assign_value(x,split_list_Dur))
    
split_list_pkt = get_percentile([33,80],'Packets')
data['Packets'] = new_df['Packets'].apply(lambda x: assign_value(x,split_list_pkt))

split_list_byte = get_percentile([25,50,75],'Bytes')
data['Bytes'] = new_df['Bytes'].apply(lambda x: assign_value(x,split_list_byte))
     
m_list = [data[name].nunique() for name in data.columns[0:5]]
def coding(x):
    code = 0
    spacesize = m_list[0]*m_list[1]*m_list[2]*m_list[3]*m_list[4]
    for i in range (0,4):
        code = code + (x[i]) * spacesize / m_list[i]
        spacesize = spacesize / m_list[i]
    return code
data['code'] = data.apply(lambda x: coding(x),axis=1)     
data['timestamp'] = pd.to_datetime(data['timestamp'],format='%Y-%m-%d %H:%M:%S')

def extract_state(host_data,width=20):
    time1 = host_data['timestamp']
    difference_list = []
    for i in range(len(host_data)):
        if i == 0:
            diff = 0
        else:
            diff = time1.iloc[i]-time1.iloc[i-1]
            diff = np.ceil(diff.value/1e6)
        difference_list.append(diff)
    host_data['time'] = difference_list
            
    ## sliding windows ##
    state_list = []
    for i in range(len(host_data)):
        j = i
        state_list.append([])
        temp_list = [host_data['code'].iloc[j]]
        time_sum = 0
        while True:
            try:
                time_sum += difference_list[j+1]
            except:
                break
            j += 1
            if time_sum<=width:
                temp_list.append(host_data['code'].iloc[j])
            else:
                break
        if len(temp_list)>=3:
            state_list[i] = temp_list
    #print ('finished: ',len(state_list))
    name = 'w%d_state' %40 
    host_data[name] = state_list
    return host_data
#Infected1 was used to model the fingerprint of infected host. 
#Nomarl1 was used to model the fingerprint of normal host
#These two fingerprint makes up the ground truth
#we used 40ms sliding window to obtain sequential data

infected1 = data[data['IP'] == '147.32.84.165']
infected1 = extract_state(infected1,width=w)

normal1 = data#[data['IP'] == '147.32.84.164']
normal1 = extract_state(normal1,width=w)

# delete the null data
state_infected1 = [l for l in infected1['w40_state'] if len(l)>0]

state_normal1 = [l for l in normal1['w40_state'] if len(l)>0]

## Sequential modal: n-grams ##

def find_ngrams(x):
    temp = []
    for i in range(len(x)):
        for j in range (len(x[i])-n+1):
            temp.append(x[i][j:j+n])    
    return temp    
grams3_normal1 = find_ngrams(state_normal1)
grams3_infected1 = find_ngrams(state_infected1)

def sort_ngrams(grams3_normals):
    ngram_dict = {}
    for gram in grams3_normals :
        grams = str(gram)[1:-1]
        if grams in ngram_dict:
            ngram_dict[grams] += 1
        else:
            ngram_dict[grams] = 1 
    sorted_ngrams = sorted(ngram_dict.items(),key = lambda x:x[1], reverse = True )
    sortedgrams_normed = [ (list[0], 1.0*list[1]/len(grams3_normals)) for list in sorted_ngrams]
    return sortedgrams_normed

fingerprint_normal1 = sort_ngrams(grams3_normal1)
fingerprint_infected1 = sort_ngrams(grams3_infected1)

fingerprint_normal = fingerprint_normal1
fingerprint_infected = fingerprint_infected1

def distance(x,y):
    x = np.array(x)
    y = np.array(y)
    dis = sum((np.divide(np.subtract(x,y),np.add(x,y)/2))**2)
    return dis

def fingerprint_matching(x,y,L):
    dis = []
    x = x[0:L]
    for ngram in y:
        dist = []
        for fp in x:
            d = distance(ngram,fp)
            dist.append(d)
        dis.append(np.min(dist))
    return dis


##calculate the nearest neighbour of the 14 testing hosts.
fmatch_test= np.zeros((13,2))
fmatch_test[0][0] = fingerprint_matching(fingerprint_infected1,grams3_normal1,L)
print(fmatch_test[0][0])
