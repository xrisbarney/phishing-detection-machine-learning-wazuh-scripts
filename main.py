# thread

import _thread as thread
import pandas as pd
from url_feature_extraction import featureExtraction

children = []
finished = False
lock = thread.allocate_lock()

data_folder = 'C:\\Users\\Chris\\Downloads\\ISCXURL2016\\'

data0 = pd.read_csv(f"{data_folder}online-valid.csv")
print(f"Shape of data: {data0.shape}")

n = 5000
phishurl = data0.sample(n=n, random_state=12).copy()
phishurl = phishurl.reset_index(drop=True)
print(f"Shape of randomly collected samples: {phishurl.shape}")

data1 = pd.read_csv(f"{data_folder}Benign_list_big_final.csv")
data1.columns = ['URLs']

legiurl = data1.sample(n=n, random_state=12).copy()
legiurl = legiurl.reset_index(drop=True)

print(f"Shape of legit URLS: {legiurl.shape}")

phish_features = []
legi_features = []


def wrapper(_id, _url, _label, group: list, *args):
    output = featureExtraction(_url, _label)
    lock.acquire()
    group.append(output)
    if finished:
        print(f"removing remaining children: {len(children)}")
    children.remove(_id)
    lock.release()


index = 0
_label = 0
_len = 1
max_thread = 100

while _len != 0 or finished is not True:
    # thread max_thread at a time
    if _len < max_thread:
        if index + 1 < legiurl.shape[0]:
            _url = legiurl['URLs'][index]
            thread.start_new_thread(wrapper, (index, _url, _label, legi_features))
            children.append(index)
            index += 1
            print(index)
        else:
            finished = True
    _len = len(children)

# converting the list to dataframe
feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
                 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Label']

legitimate = pd.DataFrame(legi_features, columns=feature_names)

# print(len(legi_features), len(children))
# Storing the extracted legitimate URLs fatures to csv file
legitimate.to_csv(f'{data_folder}legitimate.csv', index=False)
# print(legitimate)


index = 0
_label = 1
_len = 1
finished = False

while _len != 0 or finished is not True:
    # thread max_thread at a time
    if _len < max_thread:
        if index + 1 < phishurl.shape[0]:
            _url = phishurl['url'][index]
            thread.start_new_thread(wrapper, (index, _url, _label, phish_features))
            children.append(index)
            index += 1
        else:
            finished = True
    _len = len(children)

# converting the list to dataframe
feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
                 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Label']

phishing = pd.DataFrame(phish_features, columns=feature_names)

# Storing the extracted legitimate URLs fatures to csv file
phishing.to_csv(f'{data_folder}phishing.csv', index=False)

# Concatenating the dataframes into one
urldata = pd.concat([legitimate, phishing]).reset_index(drop=True)


print(f"Shape of Concatenated Data: {urldata.shape}")
# Storing the data in CSV file
urldata.to_csv(f'{data_folder}urldata.csv', index=False)
