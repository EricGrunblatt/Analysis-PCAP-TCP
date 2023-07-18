# Estimated RTT = (1 - a) (RTT) + a(new_sample)
# Recommended a: 0.125 (a = Weight)

import dpkt, sys, socket, datetime

congWindowSize = 3
numTransactions = 2
RTTWeight = 0.125
sendIP = "130.245.145.12"
recvIP = "128.208.2.198"

# Function to analyze an ack packet specifically (from sender and from receiver)
def ackContents(flowDict, currSortedFlows, flow, tran, tranIndex, index, numFlows):
    # Checks if what is being sent goes from sender to receiver
    if tran['src'] == sendIP and tran['dst'] == recvIP:

        # Confirm the correct number of handshakes occurred
        if flowDict['numHandshakes'] < 2 or flowDict['numHandshakes'] > 3:
            print("\nFLOW %s END -- SENDER: %s:%s -> RECEIVER: %s:%s -- DID NOT FINISH HANDSHAKE \n" % (index+1, tran['src'], tran['tcp'].sport, tran['dst'], tran['tcp'].dport))
            return
        elif flowDict['numHandshakes'] == 2:
            flowDict['numHandshakes'] += 1
        elif flowDict['numHandshakes'] == 3:

            # The sequence number of the current ack + the length of the data indicates the ack number sent from receiver
            # If ack was sent from receiver, that means this is the same sequence number used already
            recvAck = tran['tcp'].seq + len(tran['tcp'].data)

            if flowDict['sendCount'] < numTransactions:
                print("[Sender -> Receiver]: SEQUENCE: %s, ACK: %s, RECEIVE WINDOW SIZE: %s" % (tran['tcp'].seq, tran['tcp'].ack, flowDict['recWindowSize']))
                flowDict['sendCount'] += 1
            
            # If the previous ack is equal to the current sequence number, there is a duplicate
            if flowDict['retransmits'] == tran['tcp'].seq:
                flowDict['retransmits'] = 0
                flowDict['numDuplicateAcks'] += 1

            # Check if there were any retransmissions by seeing if the current sequence number was already used
            elif recvAck in flowDict['timeDict']:
                if tran['timestamp'] - flowDict['timeDict'][recvAck] > flowDict['newRTT']:
                    flowDict['numTimeouts'] += 1
                else: 
                    flowDict['otherRetransmissions'] += 1
            else: 
                flowDict['timeDict'][recvAck] = tran['timestamp']
            
            # Add to numPackets since congestion window size is increasing as another packet passed through
            if flowDict['congWindowIndex'] < congWindowSize:
                flowDict['numPackets'] += 1

    # Checks if what is being sent goes from receiver to sender
    elif tran['src'] == recvIP and tran['dst'] == sendIP:
        # If the max number of packets printed has not reached its limit, print new transaction contents
        if flowDict['recvCount'] < numTransactions:
            print("[Sender <- Receiver]: SEQUENCE: %s, ACK: %s, RECEIVE WINDOW SIZE: %s" % (tran['tcp'].seq, tran['tcp'].ack, flowDict['recWindowSize']))
        
        # Check if 2 * newRTT (RTO) is within 0.001 of the time where the flow start was substracted from the transaction timestamp
        if ((2 * flowDict['newRTT']) - (tran['timestamp'] - flow['flowTime']) <= 0.001 and flowDict['congWindowIndex'] < numFlows):
            # Update the current congestive window list if the buffer is greater than the previous 
            if flowDict['congWindowIndex'] == 0:
                flowDict['congWindowList'][flowDict['congWindowIndex']] = flowDict['numPackets']
            else: 
                flowDict['congWindowList'][flowDict['congWindowIndex']] = flowDict['congWindowList'][flowDict['congWindowIndex'] - 1] + flowDict['numPackets']
            flowDict['congWindowIndex'] += 1 
        
        # Use the estimated RTT formula: ((1 - a) * RTT) + (a * new_sample)
        if tran['tcp'].ack in flowDict['timeDict']:
            flowDict['oldRTT'] = flowDict['newRTT']
            tempNewRTT = tran['timestamp'] - flowDict['timeDict'][tran['tcp'].ack]
            flowDict['newRTT'] = ((1 - RTTWeight) * flowDict['oldRTT']) + (RTTWeight * tempNewRTT)

        # Update the retransmissions variable if ack is found in the ackDictionary made
        if tran['tcp'].ack in flowDict['ackDict']:
            flowDict['ackDict'][tran['tcp'].ack] += 1
            if flowDict['ackDict'][tran['tcp'].ack] == 3:
                flowDict['retransmits'] = tran['tcp'].ack
        else:
            flowDict['ackDict'][tran['tcp'].ack] = 0
        flowDict['recvCount'] += 1

# Analyzes the flows and prints the contents of them, specifically the first two transactions after the connection setup
def printContents(flowList, numFlows):
    index = 0
    for flow in flowList:
        # Contains all of the necessary information for each flow
        flowDict = {
            'numBytes': 0, 'sendCount': 0, 'recvCount': 0, 'numTimeouts': 0, 'numHandshakes': 0, 'oldRTT': 0, 'numDuplicateAcks': 0, 
            'otherRetransmissions': 0, 'newRTT': 0, 'congWindowIndex': 0, 'retransmits': 0, 'recWindowSize': 0, 'numPackets': 0, 
            'timeDict': {}, 'ackDict': {},  'congWindowList': [0] * congWindowSize,
        }
        
        # Sorts out the transactions of the current flows
        currSortedFlows = sorted(flow['flow'], key=lambda ft: ft['timestamp'])
        timestampStart = datetime.datetime.fromtimestamp(flow['flowTime'])
        tranIndex = 0

        for tran in currSortedFlows:
            flowDict['recWindowSize'] = tran['tcp'].win << flow['size']

            # Add to total number of bytes
            if tran['src'] == sendIP and tran['dst'] == recvIP:
                flowDict['numBytes'] += int(len(tran['tcp'].data) + (tran['tcp'].off*4))

            # Check attributes of current transaction
            # If syn is found in the current transaction, print that the flow is starting if src == sendIP
            # Otherwise, update the current RTT time as it will be used later to predict the estimated RTT
            if tran['syn']:
                # Source == sender ip
                if tran['src'] == sendIP and tran['dst'] == recvIP:
                    flowDict['numHandshakes'] += 1
                    flowDict['timeDict'][tran['tcp'].seq + 1] = tran['timestamp']
                    print("\nFLOW %s -- SENDER: %s:%s -> RECEIVER: %s:%s\n" % (index+1, tran['src'], tran['tcp'].sport, tran['dst'], tran['tcp'].dport))
                    print("TRANSACTION INFORMATION")

                # Source == destination ip
                elif tran['src'] == recvIP and tran['dst'] == sendIP:
                    flowDict['numHandshakes'] += 1
                    flowDict['oldRTT'] = tran['timestamp'] - flowDict['timeDict'][tran['tcp'].ack]
                    flowDict['newRTT'] = flowDict['oldRTT']
            
            # Ack found, but not fin, since fin would finalize the transaction
            # If ack is found in the transaction, print the contents of the ack packet if src == sendIP
            # Otherwise, print the contents of what the sender is receiving if src == recvIP
            elif tran['ack'] and not tran['fin']:
                ackContents(flowDict, currSortedFlows, flow, tran, tranIndex, index, numFlows)
            
            # Fin indicates the end of a flow and is where all of the part B data is printed
            elif tran['fin']:
                # Get the endtime and find number of ms it took to compute from the last flow
                # Turn the timestamps into numbers
                timestampEnd = datetime.datetime.fromtimestamp(currSortedFlows[-1]['timestamp'])
                timeStart = float(timestampStart.strftime("%Y%m%d%H%M%S.%f"))
                timeEnd = float(timestampEnd.strftime("%Y%m%d%H%M%S.%f"))
                timeDiff = (timeEnd - timeStart)
                throughput = 0
                if timeDiff != 0:
                    throughput = flowDict['numBytes'] / timeDiff
                print("\nTOTAL TIME, NUMBER OF BYTES, AND THROUGHPUT")
                print("Total Time: %.2f sec" % timeDiff)
                print("Total Number of Bytes Sent: %s bytes" % flowDict['numBytes'])
                print("Throughput: %.2f bytes/sec" % (throughput))

                # Print the estimated congestion window size
                print("\nESTIMATED CONGESTION WINDOW SIZES")
                print("Estimated Window Sizes (in packets): ",flowDict['congWindowList'])
                
                # Print the retransmission statistics
                allCases = flowDict['numTimeouts'] + flowDict['numDuplicateAcks'] + flowDict['otherRetransmissions']
                print("\nRETRANSMISSION STATISTICS")
                print("Total Retransmissions: ", allCases)
                print("Timeout retransmissions: ", flowDict['numTimeouts'])
                print("Triple duplicate ack retransmissions: ", flowDict['numDuplicateAcks'])
                print("Rare retransmission cases: %s\n" % flowDict['otherRetransmissions'])

                if index < congWindowSize-1:
                    print("-----------------------------------------------------------------")
                break
            
            tranIndex += 1

        index += 1
    return

# Reads the pcap file to store each of the flows into a list to be analyzed/printed in the printContents() function
def getFlows(pcapFile):
    flowList = []
    allFlows = {}
    numFlows = 0

    # Go through each buffer at the respective timestamp
    for timestamp, buf in pcapFile:
        ethnet = dpkt.ethernet.Ethernet(buf)
        if not isinstance(ethnet.data, dpkt.ip.IP):
            continue
        
        # Get the packets, ip addresses, ports, and timestamps with the affiliated buffer
        currPackets = {
            'syn': (ethnet.ip.data.flags & dpkt.tcp.TH_SYN),
            'ack': (ethnet.ip.data.flags & dpkt.tcp.TH_ACK),
            'fin': (ethnet.ip.data.flags & dpkt.tcp.TH_FIN),
            'src': socket.inet_ntoa(ethnet.ip.src),
            'dst': socket.inet_ntoa(ethnet.ip.dst), 
            'timestamp': timestamp,
            'tcp': ethnet.ip.data,
        }
        
        # If the receiver is sending a packet to the sender, append the packets from the destination port to the flow list
        # Get the latest timestamp since that indicates the end of the flow
        if currPackets['src'] == recvIP and currPackets['dst'] == sendIP:
            if currPackets['tcp'].dport in allFlows:
                currSyns = max(allFlows[currPackets['tcp'].dport], key=lambda ft: ft['flowTime'])
                if (not currSyns.get('iack', False)):
                    currSyns['iack'] = currPackets['tcp'].seq
                currSyns['flow'].append(currPackets)

        # If the sender is sending a packet to the receiver, get the starting time of the packet being sent (timestamp)
        elif currPackets['src'] == sendIP and currPackets['dst'] == recvIP:

            # Add to the number of flows since it is the start of a new flow. Append that information to the allFlows list
            if currPackets['syn']:
                currSyns = {
                    'flowTime': timestamp, 
                    'flow': [currPackets],
                    'size': currPackets['tcp'].opts[-1]
                }
                numFlows += 1
                if currPackets['tcp'].sport in allFlows:
                    allFlows[currPackets['tcp'].sport].append(currSyns)
                else:
                    allFlows[currPackets['tcp'].sport] = [currSyns]

            # Add the max timestamp (flowTime) to the list if anything other than a syn packet was found 
            else:
                if currPackets['tcp'].sport in allFlows:
                    currSyns = max(allFlows[currPackets['tcp'].sport], key=lambda srcp: srcp['flowTime'])
                    currSyns['flow'].append(currPackets)
        
        
    # Sort all flows by timestamp
    for flow in allFlows.values():
        flowList.extend(flow)
    flowList.sort(key=lambda ft: ft['flowTime'])
    printContents(flowList, numFlows)
    return

# This function analyzes the command line for user inputs and tries opening the pcap file. On success, it will call the getFlows function to read its contents
def pcapAnalyzer():
    # Check size of arguments to see if user inputted sender IP address, receiver IP address, or both
    if len(sys.argv) < 2:
        print("\nPlease Retry Using:\tpython analysis_pcap_tcp.py <PCAP FILE>\nAn example pcap file would be assignment2.pcap\n")
        exit(-1)
    
    # Try opening and reading pcap file to ensure the getFlows function can analyze it
    # Otherwise, send error message and exit program
    try:
        file = open(sys.argv[1], "rb")
        pcap = dpkt.pcap.Reader(file)
    except:
        print("Invalid file ", sys.argv[1])
        exit(-1)
    
    # Call the main function
    getFlows(pcap)

# Main function calls pcapAnalyzer, which starts the program
if __name__ == "__main__":
    pcapAnalyzer()

