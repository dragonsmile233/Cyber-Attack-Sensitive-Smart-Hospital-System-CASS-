import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder

# Load trained model
detect_model = tf.keras.models.load_model('./result/detectThreat.h5')

# Map predicted index to corresponding attacks
idx_attack = {0:'Normal',1:'Generic',2:'Fuzzers',3:'Exploits',4:'DoS',5:'Reconnaissance',6:'Backdoor',7:'Analysis',8:'Shellcode',9:'Worms'}

# Map categorical features into numbers
proto_idx = {'tcp':0,'udp':1,'unas':2,'arp':3,'ospf':4}
service_idx = {'dns':0,'http':1,'ftp_data':2,'smtp':3,'ftp':4,'ssh':5,'pop3':6,'ssl':7,'dhcp':8,'snmp':9,'radius':10,'irc':11}
state_idx = {'FIN':0,'CON':1,'INT':2,'REQ':3,'RST':4,'ECO':5,'CLO':6,'URH':7,'ACC':8,'PAR':9,'MAS':10,'TST':11,'no':12,'URN':13,'ECR':14,'TXD':15}


# Modify captured packets before feeding into network
def transform_packet(p,proto_idx,service_idx,state_idx):
    #pro,ser,sta = p['proto'],p['service'],p['state']
    pro,ser,sta = p['proto'].item(),p['service'].item(),p['state'].item()
    p['proto'],p['service'],p['state'] = proto_idx[pro],service_idx[ser],state_idx[sta]

    num_col = ['Spkts','dbytes','res_bdy_len','Ltime','is_sm_ips_ports','trans_depth','ct_srv_dst','Stime','dwin','Sload',
     'Dintpkt','synack','dur','ct_dst_ltm','ct_ftp_cmd','ct_state_ttl','Sintpkt','stcpb','Dload','ct_srv_src',
     'dttl','Djit','Dpkts','sbytes','is_ftp_login','tcprtt','dmeansz','sttl','smeansz','ct_dst_src_ltm','dloss',
     'ct_src_dport_ltm','swin','sloss','ct_flw_http_mthd','ct_src_ ltm','ackdat','dtcpb','ct_dst_sport_ltm','Sjit']
    
    scaler = StandardScaler()
    scaler = scaler.fit(p[num_col])
    p[num_col] = scaler.transform(p[num_col])

    # Reshape into (1,num_features)
    p = np.array(p)
    #p = p[np.newaxis,:]

    return p

# Define function to make prediction
def identify_attack(model,x,idx_attack):
    # Generate output
    pre = model.predict(x)

    # Selecting the classs as a prediction which has max probability
    y_pred = np.argmax(pre, axis=-1)
    idx = y_pred.item()
    attack = idx_attack[idx]

    return attack

if __name__ == '_main_':
    datasample = pd.read_csv('./Detect_Data/cleaned.csv')
    x,y = datasample.drop(columns=['attack_cat']), datasample[['attack_cat']]
    # We randomly select a sample p to test our result
    p = x.iloc[11:12]
    p = transform_packet(p)
    attack = identify_attack(detect_model,p,idx_attack)
    # Make Notification
    if attack!='Normal':
        print('Warning! Be careful of '+attack)
    else:
        print('Safe')