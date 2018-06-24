import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from pandas.plotting import scatter_matrix
from sklearn.cluster import KMeans
import math

def num_cluster(data):
    # get numerical data
    x = data.iloc[:,[2,6,7,8,9,12,14]]

    sse = {}
    for k in range(1, 10):
        kmeans = KMeans(n_clusters=k, max_iter=1000).fit(x)
        data["clusters"] = kmeans.labels_
        # print(data["clusters"])
        sse[k] = kmeans.inertia_  # Inertia: Sum of distances of samples to their closest cluster center
    plt.figure()
    plt.plot(list(sse.keys()), list(sse.values()))
    plt.xlabel("Number of cluster")
    plt.ylabel("SSE")
    plt.show()

def discretize(features):
    print('Discretiseing')
    disc_features = pd.DataFrame(index=features.index)
    M = []
    # defined the percentiles for numeric features
    # 2 percentile over 4 has been chosen experimentally as 25% and 75%
    percentiles = [25,75]
    # compute ranks
    r_25 = math.floor((25/100)*len(features))
    r_75 = math.floor((75/100)*len(features))
    borders = []
    #print(type(features.ix[1,1]))
    # feature mappings
    for i in range(len(features.columns)):
        # categorical feature mapping
        if type(features.ix[1,i]) is str:
            cat_map = features.ix[:,i].unique().tolist()
            M.append([])
            for f in features.ix[:,i]:
                M[i].append(cat_map.index(f))
        # numerical feature mapping
        elif type(features.ix[1,i].item(0)) is int or type(features.ix[1,i].item(0)) is float:
            sort = features.ix[:,i].sort_values(ascending=True).tolist()
            M.append([])
            borders.append((sort[r_25],sort[r_75]))
            for f in features.ix[:,i]:
                if f <= borders[0][0]:
                    M[i].append(0)
                elif f > borders[0][0] and f <= borders[0][1]:
                    M[i].append(1)
                else:
                    M[i].append(2)

    # define categorical feature mappings
    disc = list()
    code = 0
    M = np.array(M)
    spaceSize = 1

    for i in range(M.shape[0]):
        spaceSize *= len(np.unique(M[i]))
    i = 0
    M = np.transpose(M)
    M_df = pd.DataFrame(M,columns=features.columns.values)
    s = spaceSize/3;
    s1 = s/2

    M_df['code'] = M_df['f1']*s + M_df['f2']*s1

    return M_df
'''
scn10 = pd.read_csv('capture20110818.pcap.netflow.labeled',sep='\s+')
#print(scn10.head())
scn10 = scn10.rename(columns={'#Dateflow':'DateFlow','Label(LEGITIMATE:Botnet:Background)':'Label',
                                 'SrcIPAddr:Port':'Src','DstIPAddr:Port':'Dst'})
scn10 = scn10.drop('Labels',axis=1)
#print(scn10.head())
scn10[['Src_Addr','Src_Port']] = scn10['Src'].str.split(':',1,expand=True)
scn10[['Dst_Addr','Dst_Port']] = scn10['Dst'].str.split(':',1,expand=True)
scn10.drop(['Src','Dst'], inplace=True, axis=1)
scn10.to_csv('capture20110818.pcap.netflow.csv')
print(scn10.head())
'''

scn10 = pd.read_csv('capture20110818.pcap.netflow.csv')
scn10.set_index('start',inplace=True)
x = scn10[scn10['Src_Addr'] == '147.32.84.164']
scn10 = scn10.dropna()
#print(scn10.head())

#move it to preperation
scn10 = scn10.rename(columns={'->':'Direction'})
# remove background flows
scn10 = scn10[scn10.Label != 'Background']
#print(scn10.head())

# Compute number of clusters for discretization
# It has been set to 4 based on the following function
num_cluster(scn10)

# investigate one infected host
host = scn10[scn10['Src_Addr'] == '147.32.84.192']
host = host.dropna()
#print(host.head())


# visualize selected fetures to investigate relationship
fig,(ax1,ax2) = plt.subplots(1,2,sharex=False,sharey=False,figsize=(15,15))
ax1.plot(host.iloc[0:1000]['Packets'])
ax1.set_title('Number of packets sent')
sns.countplot(x='Flags',data=host,ax=ax2)
ax2.set_title('Flags')
plt.show()


# enumerate categorical features selected for discretization
features_host = pd.DataFrame()
features_host['f1'] = host['Durat']
features_host['f2'] = host['Flags']
#print(features.head())

disc_host = discretize(features_host)

features_data = pd.DataFrame()
features_data['f1'] = scn10['Durat']
features_data['f2'] = scn10['Flags']
disc_data = discretize(features_data)

fig, (ax1,ax2) = plt.subplots(1,2,sharey=False,sharex=False,figsize=(20,8))
ax1.plot(disc_host['code'].ix[0:500])
ax1.set_title('Infected Host')
ax2.plot(disc_data['code'].ix[0:500])
ax2.set_title('All Hosts')
plt.show()