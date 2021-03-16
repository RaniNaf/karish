import collections
import pyshark
import math
import numpy as np
from PIL import Image
import os


# Read Pcap file :
pcap = pyshark.FileCapture('test3.pcap')

# Every Pcap file contains packets, read single packet:
pkt = pcap[2393]


########################
#     Frame Info       #
########################

print(pkt)
print(pkt.layers)				# the packet layers
print(pkt.length)               # Packet length

print(pkt.frame_info)
print(pkt.highest_layer)        # the highest layer (HTTP)
print(pkt.number)               # Packet Number = index + 1
print(pkt.sniff_timestamp)
print(pkt.transport_layer)      # Transport layer: UDP, TCP, etc.

print(pkt.frame_info.time)
print(pkt.frame_info.time_delta)
print(pkt.frame_info.time_relative)
print(pkt.frame_info.protocols)


#######################
#     ETH Layer       #
#######################

print(pkt[0])       # OR:
print(pkt['eth'])   # OR:
print(pkt.eth)

print(pkt.eth.dst)  # Mac Address dst
print(pkt.eth.src)  # Mac Address src

######################
#     IP Layer       #
######################

print(pkt[1])       # OR:
print(pkt['ip'])    # OR:
print(pkt.ip)

print(pkt.ip.dst)      # IP dst
print(pkt.ip.src)      # IP src
print(pkt.ip.ttl)      # Ip time to live
print(pkt.ip.hdr_len)  # Ip Header length
print(pkt.ip.proto)    # Ip Protocol (17 = UDP,


#######################
#   Transport Layer   #
#######################

print(pkt.transport_layer)

###  UDP  ###

print(pkt[2])        # OR:
print(pkt['udp'])    # OR:
print(pkt.udp)

print(pkt.udp.dstport)      # Port dst
print(pkt.udp.srcport)      # Port src
print(pkt.udp.length)       # Port len


###  TCP  ###

pkt = pcap[6482]  # TCP packet

print(pkt[2])        # OR:
print(pkt['tcp'])    # OR:
print(pkt.tcp)

print(pkt.tcp.dstport)      # Port dst
print(pkt.tcp.srcport)      # Port src
print(pkt.tcp.stream)      # Stream Index
print(pkt.tcp.seq)        # Sequence Number
print(pkt.tcp.hdr_len)      # TCP header length
print(pkt.tcp.flags)      # TCP flags
print(pkt.tcp.window_size_value)      # window
print('time_delta  -', pkt.tcp.time_delta)      # time since previous frame in this TCP Stream
print('time_relative  -', pkt.tcp.time_relative)      # time since first frame in this TCP Stream


########################
#   Common Protocols   #
########################

###  DNS  ###

# check for layer
if "DNS" in pkt:
    print("DNS Packet")

# single layer of the packet:
print(pkt.dns)

# the fields of the layer:
print(pkt.dns.field_names)
print(pkt.dns.qry_name)
print(pkt.dns.a)  # if its DNS response packet
print(pkt.dns.flags)


# the type of the values:
print(type(pkt.dns.qry_name))
print(type(pkt.dns.a))
print(type(pkt.dns.flags))

# convert to string
str_dns = str(pkt.dns.qry_name)
print(str_dns)
print(type(str_dns))


###  HTTP  ###

########################>

print(dir(pkt))
print((pkt.tcp.field_names))


#######################
#   Only Summaries   #
#######################


# Read Pcap file only summaries:
pcap = pyshark.FileCapture('test3.pcap', only_summaries=True)

pkt = pcap[29]

print(pkt.summary_line)
print(type(pkt.summary_line))

print(pkt.no)
print(pkt.time)
print(pkt.source)
print(pkt.destination)
print(pkt.protocol)
print(pkt.length)
print(pkt.info)

#######################
#   Capture Options   #
#######################

# Read Pcap file as JSON:
pcap = pyshark.FileCapture('test3.pcap', use_json=True)

# Read Pcap file only summaries:
pcap = pyshark.FileCapture('test3.pcap', only_summaries=True)

# Capture Live:
pcap = pyshark.LiveCapture('Wi-Fi')  # insert the network name


# Filtering the Pcap file:
pcap = pyshark.FileCapture('test3.pcap', display_filter="dns")


######################
#   Some Functions   #
######################

## DNS Counter  ##

def dnscounter(pcapfile):

    # Read Pcap file :
    pcap = pyshark.FileCapture(pcapfile)
    dnss = []
    try:
        for p in pcap:
            if "DNS" in p:
                # print(p.dns.qry_name)
                dnss.append(str(p.dns.qry_name))
    except:
        pass
    counter = collections.Counter(dnss)
    pcap.close()

    return (counter)


dnss_c = dnscounter('test3.pcap')
print(dnss_c.most_common()[0])

## Protocol Counter  ##


def procounter(pcapfile):

    # Read Pcap file :
    pcap = pyshark.FileCapture(pcapfile, only_summaries=True)
    pro = []
    try:
        for p in pcap:
            line = str(p).split(" ")
            pro.append(line[4])
    except:
        pass
    counter = collections.Counter(pro)
    pcap.close()

    return (counter)

pro_c = procounter('test3.pcap')
print(pro_c.most_common()[1])


## PCAP TO BINARY TO IMAGE ##


pcap = pyshark.FileCapture('test3.pcap')
f = open("temp.txt", 'w')
f.write(str(pcap[9]))
f.close()

p = pcap[9]


def getBinaryData(filename):

    binary_values = []

    with open("temp.txt", 'rb') as fileobject:
        # read file byte by byte
        data = fileobject.read(1)

        while data != b'':
            binary_values.append(ord(data))
            data = fileobject.read(1)

    return binary_values


def get_size2(data_length, width=None):
	# source Malware images: visualization and automatic classification by L. Nataraj
	# url : http://dl.acm.org/citation.cfm?id=2016908

	if width is None: # with don't specified any with value

		size = data_length

		if (size < 32*32):
			width = 32
		elif (32*32 <= size <= 64 * 64):
			width = 64
		elif (64 * 64 <= size <= 128 * 128):
			width = 128
		elif (128 * 128 <= size <= 256 * 256):
			width = 256
		elif (256 * 256 <= size <= 384 * 384):
			width = 384
		elif (384 * 384 <= size <= 512 * 512):
			width = 512
		elif (512 * 512 <= size <= 768 * 768):
			width = 768
		else:
			width = 1024

		height = int(size / width) + 1

	else:
		width  = int(math.sqrt(data_length)) + 1
		height = width

	return (width, height)


def zeroFill(bin_data):

    a = bin_data
    size = get_size(len(a))[0]
    n_zeros = size * size - len(a)

    for i in range(n_zeros):
        a.append(0)

    z = np.array(a)
    fz = z.reshape(size,size)
    return (fz)


def save_file(filename, data, size, image_type):

	try:
		image = Image.new(image_type, size)
		image.putdata(data)

		# setup output filename
		dirname     = os.path.dirname(filename)
		name, _     = os.path.splitext(filename)
		name        = os.path.basename(name)
		imagename   = dirname + os.sep + image_type + os.sep + name + '_'+image_type+ '.png'
		os.makedirs(os.path.dirname(imagename), exist_ok=True)

		image.save(imagename)
		print('The file', imagename, 'saved.')
	except Exception as err:
		print(err)


def get_size(data_length, width=None):
	# source Malware images: visualization and automatic classification by L. Nataraj
	# url : http://dl.acm.org/citation.cfm?id=2016908

	if width is None: # with don't specified any with value

		size = data_length

		if (size < 10240):
			width = 32
		elif (10240 <= size <= 10240 * 3):
			width = 64
		elif (10240 * 3 <= size <= 10240 * 6):
			width = 128
		elif (10240 * 6 <= size <= 10240 * 10):
			width = 256
		elif (10240 * 10 <= size <= 10240 * 20):
			width = 384
		elif (10240 * 20 <= size <= 10240 * 50):
			width = 512
		elif (10240 * 50 <= size <= 10240 * 100):
			width = 768
		else:
			width = 1024

		height = int(size / width) + 1

	else:
		width  = int(math.sqrt(data_length)) + 1
		height = width

	return (width, height)


def createGreyScaleImage(filename, width=None):
	"""
	Create greyscale image from binary data. Use given with if defined or create square size image from binary data.
	:param filename: image filename
	"""
	greyscale_data = getBinaryData(filename)
	size = get_size(len(greyscale_data), width)
	save_file(filename, greyscale_data, size, 'L')


# x = getBinaryData('temp.txt')
# xz = zeroFill(x)
#
# plt.imshow(xz, cmap='gray')
# plt.show()

createGreyScaleImage("temp.txt")

###########################################################33

print(dir(pkt))
print((pkt.tcp.field_names))

# don't forget to close the file:
pcap.close()