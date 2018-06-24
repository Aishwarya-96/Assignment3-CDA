import pandas as pd
import numpy as np
import random
import math
import time
import matplotlib.pyplot as plt


def minWise(data,k):
    reservoir = []
    sample = []
    for index,d in data.iterrows():
        rnd = random.uniform(0,1)
        if len(reservoir) < k:
            reservoir.append(rnd)
            sample.append(d)
        try:
            idx = next(x[0] for x in enumerate(reservoir) if x[1] > rnd)
            reservoir[idx] = rnd
            sample[idx] = d
        except StopIteration:
            continue
        except ValueError:
            continue
    return pd.DataFrame(sample,columns=data.columns.values,index=range(k))

'''
# preporecessing step
netflw1 = pd.read_csv('capture20110815-2.pcap.netflow.csv')
print(netflw1.head())
#print(netflw1.columns.values)
#netflw1 = netflw1.drop('->',axis=1)
#netflw1 = netflw1.rename(columns={'#Date_flow':'DateFlow','Label(LEGITIMATE:Botnet:Background)':'Label',
#                                  'Src_IP_Addr:Port':'Src','Dst_IP_Addr:Port':'Dst'})

print(len(netflw1))
#netslice = netflw1.loc[1:30,:]
netflw1[['Src_Addr','Src_Port']] = netflw1['Src'].str.split(':',1,expand=True)
netflw1[['Dst_Addr','Dst_Port']] = netflw1['Dst'].str.split(':',1,expand=True)
netflw1.drop(['Src','Dst'], inplace=True, axis=1)
netflw1.to_csv('capture20110815.pcap.netflow.csv')
'''
# netflow file has been pre-processed. src and dst ip addressed have been splited from corresponding port addresses
# read pre-processed file
df = pd.read_csv('capture20110815.pcap.netflow.csv')
#print(df.head())

# count ip ocurrences to find infected host. the most common ip address has been chosen as infected host
# which indicates the most frequent connections

# drop other connections
df = df[(df['Src_Addr'] == '147.32.84.229') | (df['Dst_Addr'] == '147.32.84.229')]
df = df.dropna()
#print(len(df))
#print(df.head())

# calculate ip address frequency which are connected with the infected host
ip_count = {}
# count outgoing connections
for ip in df['Dst_Addr']:
    if ip == '147.32.84.229':
        continue
    if ip in ip_count.keys():
        ip_count[ip] += 1
    else:
        ip_count[ip] = 1

# count in coming connections
for ip in df['Src_Addr']:
    if ip == '147.32.84.229':
        continue
    if ip in ip_count.keys():
        ip_count[ip] += 1
    else:
        ip_count[ip] = 1

#for ip in ip_count:
#    print('IP: {}\t Count: {}'.format(ip,ip_count[ip]))
top_IPs = sorted(ip_count, key=ip_count.get, reverse=True)[:10]

# Statistics of distribution
dist = []
sample = []
sample.append(ip_count)

# top 10 IP addresses
print('\nTop 10 IP Adresses with relative frequencies\n')
for ip in top_IPs:
    print('IP: {}\tCount: {}'.format(ip,ip_count[ip]))

# plot histogram of IP addresses
plt.plot(list(ip_count.values()))
plt.title('Frequency Count')
plt.show()
estimation = []
# Sampling
for k in range(5000,75000,15000):
    print('\nSAmple Size k: {}'.format(k))
    start = time.time()
    mw10000 = minWise(df,k)
    ellapsed_time = time.strftime("%H:%M:%S", time.gmtime(time.time() - start))
    print('Sample generation time : {}'.format(ellapsed_time))

    ip_count_sample = {}
    for ip in mw10000['Dst_Addr']:
        if ip == '147.32.84.229':
            continue
        if ip in ip_count_sample.keys():
            ip_count_sample[ip] += 1
        else:
            ip_count_sample[ip] = 1

    # count in coming connections
    for ip in mw10000['Src_Addr']:
        if ip == '147.32.84.229':
            continue
        if ip in ip_count_sample.keys():
            ip_count_sample[ip] += 1
        else:
            ip_count_sample[ip] = 1

    ip_estimate_sample = {}
    top_IPs_sample = sorted(ip_count_sample, key=ip_count_sample.get, reverse=True)[:10]
    mean_sample = sum(ip_count_sample[ip] for ip in ip_count_sample)/len(ip_count_sample)

    for ip in ip_count_sample:
        ip_estimate_sample[ip] = math.ceil((ip_count_sample[ip]/len(mw10000))*len(df))

    estimation.append(ip_estimate_sample)

    # compute approximation error statistics
    apprx_err = []
    for ip in ip_estimate_sample:
        apprx_err.append(ip_estimate_sample[ip] - ip_count[ip])

    print('Approximation error mean: {}\nStandard Deviation: {}'
          .format(round(np.mean(apprx_err),3),round(np.std(apprx_err),3)))

# Top 10 IP Addresses from one of samples
print('\nTop 10 Sampled IP Adresses from sample size {}'.format(k))
top_IPs_sample = sorted(estimation[-1], key=estimation[-1].get, reverse=True)[:10]
for ip in top_IPs_sample:
    print('IP: {}\tCount: {}\tEstimation: {}'.format(ip,ip_count[ip],round(estimation[-1][ip],3)))