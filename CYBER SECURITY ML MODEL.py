#!/usr/bin/env python
# coding: utf-8

# In[31]:


import pandas as pd
df=pd.read_csv("C:\\Users\\Dell\\Desktop\\malicious_phish.csv")
df.head(10)


# types of URLs
# 
# Benign URLs: 
# These are safe to browse URLs. 
# 
# Malware URLs: 
# These type of URLs inject malware into the victim’s system once he/she visit such URLs. 
# 
# Defacement URLs: 
# Defacement URLs are generally created by hackers with the intention of breaking into a web server and replacing the hosted website with one of their own, using techniques such as code injection, cross-site scripting, etc. Common targets of defacement URLs are religious websites, government websites, bank websites, and corporate websites. 
# 
# Phishing URLs:
# By creating phishing URLs, hackers try to steal sensitive personal or financial information such as login credentials, credit card numbers, internet banking details, etc. 

# WORDCLOUD OF URLs
# * technique of NLP
# word cloud of benign URLs is pretty obvious having frequent tokens such as html, com, org, wiki etc. 
# Phishing URLs have frequent tokens as tools, ietf, www, index, battle, net whereas html, org, html are higher frequency tokens as these URLs try to mimick original URLs for deceiving the users.
# The word cloud of malware URLs has higher frequency tokens of exe, E7, BB, MOZI. These tokens are also obvious as malware URLs try to install trojans in the form of executable files over the users’ system once the user visits those URLs.
# 
# The defacement URLs’ intention is to modify the original website’s code and this is the reason that tokens in its word cloud are more common development terms such as index, php, itemid, https, option, etc.

# In[3]:


# importing necessary libraries
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.model_selection import train_test_split
import xgboost as xgb
from lightgbm import LGBMClassifier
from wordcloud import WordCloud
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score


# In[4]:


pip install xgboost


# In[5]:


# importing necessary libraries
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.model_selection import train_test_split
import xgboost as xgb
from lightgbm import LGBMClassifier
from wordcloud import WordCloud
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score


# In[6]:


pip install xgboost --user


# In[7]:


# importing necessary libraries
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.model_selection import train_test_split
import xgboost as xgb
from lightgbm import LGBMClassifier
from wordcloud import WordCloud
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score


# In[8]:


pip install lightgbm --user


# In[9]:


# importing necessary libraries
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.model_selection import train_test_split
import xgboost as xgb
from lightgbm import LGBMClassifier
from wordcloud import WordCloud
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score


# In[13]:


pip install --upgrade dask
pip install --upgrade pandas


# In[14]:


from lightgbm import LGBMClassifier


# In[15]:


from wordcloud import WordCloud


# In[16]:


import wordcloud


# In[17]:


from wordcloud import WordCloud


# In[18]:


import itertools


# In[19]:


from sklearn.metrics import classification_report,confusion_matrix, accuracy_score


# In[20]:


# importing necessary libraries
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.model_selection import train_test_split
import xgboost as xgb
from lightgbm import LGBMClassifier
from wordcloud import WordCloud
import itertools
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score


# FEATURE ENGINEERING
#  
# there are several ways to distinguish a malicious URL from a benign one
#  
# has_ip_address--Generally cyber attackers use an IP address in place of the domain name to hide the identity of the website
# abnormal_url--For a legitimate website, identity is typically part of its URL.
# google_index--Google indexes web pages to make them searchable for users when they perform a search,this feature checks that
# 
# Count . -- The phishing or malware websites generally use more than two sub-domains in the URL. Each domain is separated by dot (.). If any URL contains more than three dots(.), then it increases the probability of a malicious site.
#  
# Count-www--Generally most of the safe websites have one www in its URL. This feature helps in detecting malicious websites if the URL has no or more than one www in its URL.
# 
# count@--The presence of the “@” symbol in the URL ignores everything previous to it.
#  
# Count_dir-- The presence of multiple directories in the URL generally indicates suspicious websites.
# 
# Count_embed_domain--The number of the embedded domains can be helpful in detecting malicious URLs. It can be done by checking the occurrence of “//” in the URL.
# 
# Suspicious words in URL-- Malicious URLs generally contain suspicious words in the URL 
# 
# Short_url--This feature is created to identify whether the URL uses URL shortening services like bit. \ly, goo.gl, go2l.ink
# 
# Count_https--Generally malicious URLs do not use HTTPS protocols as it generally requires user credentials and ensures that the website is safe for transactions. So, the presence or absence of HTTPS protocol in the URL is an important feature.
# 
# Count%-- As we know URLs cannot contain spaces. URL encoding normally replaces spaces with symbol (%). Safe sites generally contain less number of spaces whereas malicious websites generally contain more spaces in their URL hence more number of %.
# 
# Count?--- This symbol(?) in URL denotes a query string that contains the data to be passed to the server. More number of ? in URL definitely indicates suspicious URL.
# 
# Count- -- Phishers or cybercriminals generally add dashes(-) in prefix or suffix of the brand name so that it looks genuine URL. For example. 
# 
# Count= -- Presence of (=) in URL indicates passing of variable values from one form page to another. It is considered as riskier in URL as anyone can change the values to modify the page.
# 
# url_length -- Attackers generally use long URLs to hide the domain name. 
# (safe URL length = 74)
# 
# hostname_length -- hostname length is also important for detecting malicious URLs.
# 
# First directory length -- length of the first directory in the URL. So looking for the first ‘/’ and counting the length of the URL till this is first directory length.
# 
# Length of top-level domain--  length of TLD is also important in identifying malicious URLs. TLDs in the range from 2 to 3 generally indicate safe URLs.
# 
# Count_digits-- Safe URLs generally do not have digits 
# 
# Count_letters--attackers try to increase the length of the URL to hide the domain name by increasing the number of letters and digits in the URL.

# In[32]:


df=pd.read_csv("C:\\Users\\Dell\\Desktop\\malicious_phish.csv")
df.head(10)


# In[33]:


# we'll use a module in python named re, it helps us scan through a string for a match to given input 
import re
# have_ip_adress--- 1
def having_ip_address(url):
    # Regular expression for matching IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, url)
    if bool(match)==True:
        return 1
    else:
        return 0
#applying function to each element in the df
df["has_ip"]=df["url"].apply(lambda i:having_ip_address(i))
df


# In[34]:


from urllib.parse import urlparse
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0
df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
df


# In[35]:


pip install googlesearch-python


# In[36]:


from googlesearch import search
# performs search in google


# In[37]:


# function to determine wether a url in indexed by google or not
def google_index(url):
    res = search(url, 10)# returns top 10 searches
    if res:
        return 1
    else:
        return 0
df['google_index'] = df['url'].apply(lambda i: google_index(i))
df


# In[38]:


# counting number of .(>3-malicious)
def cdot(url):
    cdot = url.count('.')
    return cdot
df['count.'] = df['url'].apply(lambda i: cdot(i))
df


# In[39]:


def www(url):
    c=url.count('www')
    return c
df['count-www'] = df['url'].apply(lambda i: www(i))
df


# In[40]:


def cat(url):
    c=url.count('@')
    return c
df['count@'] = df['url'].apply(lambda i: cat(i))
df


# In[41]:


def ndir(url):
    ndir = urlparse(url).path# exptracts the path from the url it parses through
    return ndir.count('/')# counts the number of / in the path---multiple /--multiple directories--malicious url
df['count_dir'] = df['url'].apply(lambda i: ndir(i))
df


# In[42]:


def ndom(url):
    ndom = urlparse(url).path
    return ndom.count('//')
df['count_embedded_dom'] = df['url'].apply(lambda i: ndom(i))
df


# In[47]:


# function to check if a url uses shortening services eg. bitly etc
def shorturl(url):
    cw = ['bit.ly','goo.gl','t.co']
    if urlparse(url).netloc in cw:
        return 1
    else:
        return 0
    
df['is_short'] = df['url'].apply(lambda i: shorturl(i))
df


# In[48]:


df1=df[df['is_short']==1]
df1


# In[49]:


df


# In[51]:


def https(url):
    c=url.count('https')
    return c
df['count-https'] = df['url'].apply(lambda i : https(i))
df
df1=df[df['count-https']==1]
df1


# In[52]:


df


# In[53]:


def per(url):
    c=url.count('%')
    return c
df['count%'] = df['url'].apply(lambda i : per(i))
df


# In[54]:


def ques(url):
    return url.count('?')
df['count?'] = df['url'].apply(lambda i: ques(i))
df


# In[55]:


df.head(20)


# In[56]:


df1=df[df['count%']==1]
df1


# In[57]:


df


# In[58]:


def dash(url):
    return url.count('-')
df['count-'] = df['url'].apply(lambda i: dash(i))
df


# In[59]:


def equal(url):
    return url.count('=')
df['count='] = df['url'].apply(lambda i: equal(i))
df


# In[60]:


# function to find length of url
def url_length(url):
    return len(str(url))
df['url_length'] = df['url'].apply(lambda i: url_length(i))
df


# In[61]:


# finding length of hostname
def hname(url):
    l=len(urlparse(url).netloc)
    return l
df['hostname_length'] = df['url'].apply(lambda i: hname(i))
df
#netloc attribute represents the network location part of the URL, which typically includes the domain name and port(if given)


# In[62]:


def suspicious_words(url):
    sw = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',url)
    # search for these suspicious words in the url
    if sw:
        return 1
    else:
        return 0
df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
df


# In[67]:


def dig(url):
    c = 0
    for i in url:
        if i.isnumeric():
            c=c+1
    return c
df['count-digits']= df['url'].apply(lambda i: dig(i))
df


# In[68]:


def let(url):
    l = 0
    for i in url:
        if i.isalpha():
            l= l + 1
    return l
df['count-letters']= df['url'].apply(lambda i: let(i))
df


# In[69]:


pip install tld


# In[70]:


from urllib.parse import urlparse
from tld import get_tld
import os.path


# In[71]:


#First Directory Length
def fd_length(url):
    path= urlparse(url).path
    try:
        return len(path.split('/')[1])# before the first / is the first dir
    except:
        return 0
df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
df


# In[73]:


df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1
df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
# length pf top level domain
df


# In[74]:


df


# In[75]:


# label encoding
from sklearn.preprocessing import LabelEncoder
lb_make = LabelEncoder()
df["type_code"] = lb_make.fit_transform(df["type"])
df


# In[77]:


# segregating feature and target variables
#Predictor Variables
# filtering out google_index as it has only 1 value
X = df[['url','has_ip','abnormal_url', 'count.', 'count-www', 'count@',
       'count_dir', 'count_embedded_dom', 'is_short', 'count-https',
       'count%', 'count?', 'count-', 'count=', 'url_length',
       'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
       'count-letters']]
#Target Variable
y = df['type_code']
df


# In[78]:


# training and test split
# this dataset is imbalanced, ie. it contains certain percentages of benogn, phishing, malware etc urls while splitting 
# we need to take care that the splitting occurs evenly so we'll be using a satisfaction variable
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2,shuffle=True, random_state=5)


# In[79]:


X_train


# In[ ]:




