import scapy.all as scapy
from datetime import datetime

start_time = None


def extract_sbytes(pkt):
    if pkt.haslayer('IP'):
        ip_len = pkt['IP'].len
        ip_header_len = pkt['IP'].ihl * 4
        if pkt.haslayer('TCP'):
            transport_len = ip_len - ip_header_len
        elif pkt.haslayer('UDP'):
            transport_len = pkt['UDP'].len - 8
        else:
            transport_len = 0
    else:
        transport_len = 0
    return transport_len


def extract_dbytes(pkt):
    if pkt.haslayer('UDP'):
        payload_len = len(pkt['UDP'].payload)
        return payload_len
    elif pkt.haslayer('TCP'):
        payload_len = len(pkt['TCP'].payload)
        return payload_len
    else:
        return 0


def extract_bytes(packet):
    sbytes = 0
    dbytes = 0
    if packet.haslayer('TCP'):
        sbytes += len(packet['TCP'].payload)
        dbytes += len(packet['TCP'].payload)

    elif packet.haslayer('UDP'):
        sbytes += len(packet['UDP'].payload)
        dbytes += len(packet['UDP'].payload)

    return sbytes, dbytes


feature = ['proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload',
           'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
           'Sjit',
           'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports',
           'ct_state_ttl',
           'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm',
           'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm']


def extract_feature_tcp(pkt, feature):
    global start_time
    features = {}

    if start_time is None:
        start_time = pkt.time
    current_time = pkt.time
    total_duration = current_time - start_time
    dur = total_duration

    srcip = pkt.src
    dstip = pkt.dst

    tcp = pkt['TCP']
    features['proto'] = 'tcp'
    features['state'] = tcp.flags
    features['sbytes'] = extract_sbytes(pkt)  # Source to destination bytes
    features['dbytes'] = extract_dbytes(pkt)  # Destination to source bytes
    features['sttl'] = pkt['IP'].ttl  # Source to destination time to live
    features['dttl'] = pkt['IP'].ttl  # Destination to source time to live
    sloss = 0  # Source packets retransmitted or dropped
    dloss = 0  # Destination packets retransmitted or dropped
    service = tcp.dport  # http, ftp, ssh, dns ..,else (-)
    Sload = 1  # Source bits per second
    Dload = 1  # Destination bits per second

    features['is_ftp_login'] = 0  # If the ftp session is accessed by user and password then 1 else 0.
    features['ct_ftp_cmd'] = 0  # No of flows that has a command in ftp session.
    features[
        'ct_srv_src'] = 1  # No. of connections that contain the same service (14) and source address (1) in 100 connections according to the last time (26).
    features[
        'ct_srv_dst'] = 1  # No. of connections that contain the same service (14) and destination address (3) in 100 connections according to the last time (26).
    features[
        'ct_dst_ltm'] = 1  # No. of connections of the same destination address (3) in 100 connections according to the last time (26).
    features[
        'ct_src_ltm'] = 1  # No. of connections of the same source address (1) in 100 connections according to the last time (26).
    features[
        'ct_src_dport_ltm'] = 1  # No of connections of the same source address (1) and the destination port (4) in 100 connections according to the last time (26).
    features[
        'ct_dst_sport_ltm'] = 1  # No of connections of the same destination address (3) and the source port (2) in 100 connections according to the last time (26).
    features[
        'ct_dst_src_ltm'] = 1  # No of connections of the same source (1) and the destination (3) address in in 100 connections according to the last time (26).

    return features


'''
    Sload = #Source bits per second
    Dload = #Destination bits per second
    Spkts = #Source to destination packet count
    Dpkts = #Destination to source packet count
    swin = #Source TCP window advertisement
    dwin = #Destination TCP window advertisement
    stcpb = #Source TCP sequence number
    dtcpb = #Destination TCP sequence number
    smeansz = #Mean of the flow packet size transmitted by the src
    dmeansz = #Mean of the flow packet size transmitted by the dst
    trans_depth = #the depth into the connection of http request/response transaction
    res_bdy_len = #The content size of the data transferred from the server’s http service

    Sjit = #Source jitter (mSec)
    Djit = #Destination jitter (mSec)
    Stime = #record start time
    Ltime = #record last time
    Sintpkt = #Source inter-packet arrival time (mSec)
    Dintpkt = #Destination inter-packet arrival time (mSec)
    tcprtt = #The sum of ’synack’ and ’ackdat’ of the TCP.
    synack = #The time between the SYN and the SYN_ACK packets of the TCP.
    ackdat = #The time between the SYN_ACK and the ACK packets of the TCP.

    is_sm_ips_ports = #If source (1) equals to destination (3)IP addresses and port numbers (2)(4) are equal, this variable takes value 1 else 0
    ct_state_ttl = #No. for each state (6) according to specific range of values for source/destination time to live (10) (11).
    ct_flw_http_mthd = # No. of flows that has methods such as Get and Post in http service.


'''


def extract_features1(pkt):
    global start_time

    if start_time is None:
        start_time = pkt.time
    features = {}
    # Duration
    current_time = pkt.time
    total_duration = current_time - start_time
    features['dur'] = total_duration

    # Source Port
    if pkt.haslayer('TCP'):
        features['sport'] = pkt['TCP'].sport
    elif pkt.haslayer('UDP'):
        features['sport'] = pkt['UDP'].sport

    # Destination Port
    if pkt.haslayer('TCP'):
        features['dsport'] = pkt['TCP'].dport
    elif pkt.haslayer('UDP'):
        features['dsport'] = pkt['UDP'].dport
    else:
        features['dsport'] = 0

    # Protocol
    if pkt.haslayer('TCP'):
        features['proto'] = 'tcp'
        features['state'] = pkt['TCP'].flags
    elif pkt.haslayer('UDP'):
        features['proto'] = 'udp'
        # features['state'] = pkt['UDP'].flags
    elif pkt.haslayer('ARP'):
        features['proto'] = 'arp'
    elif pkt.haslayer('UNAS'):
        features['proto'] = 'unas'
    else:
        features['proto'] = '-'

    # Source Bytes
    features['sbytes'] = extract_sbytes(pkt)
    # Destination Bytes
    features['dbytes'] = extract_dbytes(pkt)

    return features


def main():
    print('Start Monitoring......')

    sniffer = scapy.sniff(filter='tcp', prn=lambda x: x.show(), count=5)
    scapy.wrpcap('./packets.pcap', sniffer)

    f = open('./packet.txt', 'a')
    explain = '\n proto: tcp \n sbytes: Source to destination bytes \n dbytes: extract_dbytes(pkt) #Destination to source bytes \n sttl: Source to destination time to live \n dttl: Destination to source time to live \n sloss: Source packets retransmitted or dropped \n dloss: Destination packets retransmitted or dropped \n service: http, ftp, ssh, dns ..,else (-) \n is_ftp_login : If the ftp session is accessed by user and password then 1 else 0. \n ct_ftp_cmd : No of flows that has a command in ftp session. \n ct_srv_src : No. of connections that contain the same service (14) and source address (1) in 100 connections according to the last time (26). \n ct_srv_dst : No. of connections that contain the same service (14) and destination address (3) in 100 connections according to the last time (26). \n ct_dst_ltm : No. of connections of the same destination address (3) in 100 connections according to the last time (26). \n ct_src_ltm : No. of connections of the same source address (1) in 100 connections according to the last time (26). \n ct_src_dport_ltm : No of connections of the same source address (1) and the destination port (4) in 100 connections according to the last time (26). \n ct_dst_sport_ltm : No of connections of the same destination address (3) and the source port (2) in 100 connections according to the last time (26). \n ct_dst_src_ltm: No of connections of the same source (1) and the destination (3) address in in 100 connections according to the last time (26).\n Sload : Source bits per second \n Dload : Destination bits per second \n Spkts : Source to destination packet count \n Dpkts : Destination to source packet count \n swin : Source TCP window advertisement \n dwin : Destination TCP window advertisement \n stcpb : Source TCP sequence number \n dtcpb : Destination TCP sequence number \n smeansz : Mean of the flow packet size transmitted by the src \n dmeansz : Mean of the flow packet size transmitted by the dst \n trans_depth : the depth into the connection of http request/response transaction \n res_bdy_len : The content size of the data transferred from the server’s http service \n Sjit : Source jitter (mSec) \n Djit : Destination jitter (mSec) \n Stime : record start time \n Ltime : record last time \n Sintpkt : Source inter-packet arrival time (mSec) \n Dintpkt : Destination inter-packet arrival time (mSec) \n tcprtt : The sum of ’synack’ and ’ackdat’ of the TCP. \n synack : The time between the SYN and the SYN_ACK packets of the TCP. \n ackdat : The time between the SYN_ACK and the ACK packets of the TCP. \n is_sm_ips_ports : If source (1) equals to destination (3)IP addresses and port numbers (2)(4) are equal, this variable takes value 1 else 0 \n ct_state_ttl : No. for each state (6) according to specific range of values for source/destination time to live (10) (11). \n ct_flw_http_mthd : No. of flows that has methods such as Get and Post in http service.'
    f.write(
        "--------------------------------------------------Explain params-------------------------------------------------- \n")
    f.write(explain)
    f.write('\n')
    f.write(
        '--------------------------------------------------Packets captured-------------------------------------------------- \n')
    f.write('\n')
    for pkt in sniffer:
        f.write(str(extract_feature_tcp(pkt, feature)))
        f.write('\n')
    f.close()

    print('Completed!')


if __name__ == '__main__':
    main()