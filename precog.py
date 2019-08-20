#read file
import subprocess
import os
import socket

#open the test file of output
#f = open('results4', "r")
subprocess.call(["cat /nsm/bro/logs/current/http_eno2.log | bro-cut id.orig_h host referrer | grep -v '#' > /tmp/results"],shell=True)
f = open('/tmp/results', "r")
lines = f.readlines()
f.close()

privIP_list=[]

count = 0
#b = open('badlist', "r")
#adver_domains = b.readlines()
counting = 0 
first_run = 0

#trap error when looking up hostname by IP
def lookup(ip):
   try:
      return socket.gethostbyaddr(ip)
   except socket.herror:
      return None, None, None


for line in lines:
   #convert the line into a readable string
   line = line.strip().lower().split()
   #set the private IP
   priv_ip=line[0]
   #set the host the private IP is going to
   host=line[1]
   #set just the domain name of the host the IP is going to
   test=line[1].strip().split(".")
   #getting length of the host
   end=len(test)
   #grab just the host name before it's suffix (.com, .net, etc) 
   ckdomain=test[end-2]
   #print("domain checking is"),
   #print(ckdomain)
   #open the badlist file which is a list of known advertisers
   with open('badlist') as adver:
      #if the domain name in our list is in the known advertisers list, then output
      if ckdomain in adver.read():
         if first_run == 0:
            first_run = 1
            #set old IP address to New IP address for checks
            old_ip = priv_ip
            counting = counting + 1
            #append the private IP address to the privIP list 
            privIP_list.append(priv_ip)
            #get the index value of where the private IP address is in the IP list
            IPN=privIP_list.index(priv_ip)
            #set the count to the element next to the private IP address, only insert on first run)
            privIP_list.insert(IPN+1,counting)
            #count_list.append(counting)
         #check to see if the current IP address is in the list, has it been seen before?
         if priv_ip in privIP_list:
            #privIP_list.append(priv_ip)
            #the IPN is the Index of the IP address, where is the IP in our list?
            IPN=privIP_list.index(priv_ip)
            #the count is equal to the value next to where the IP address is, in the list
            counting=privIP_list[IPN+1]+1
            #overwrite value of count that is next to the IP address, this is how we keep track of what IP address has what count
            privIP_list[IPN+1] = counting
            #count_list.append(counting)
          #  print('%s' " has " '%s' "is in the advertising domain list" % (priv_ip, host))
         #if the IP hasn't been seen before, it is new.  reset the count and add the new entry into the list after the IP,Count of existing
         if priv_ip not in privIP_list:
            counting = 1
            #print(" There is a new IP adderss '%s' with a count of '%s'" % (priv_ip,counting))
            privIP_list.append(priv_ip)
            #for x in range(len(privIP_list)):
            #   print (privIP_list[x])
            IPN=privIP_list.index(priv_ip)
            #print("The IPN for new is '%s'" % (IPN))
            privIP_list.insert(IPN+1,counting)
            old_ip=priv_ip            
#Finally, iterate through the list, if the index number is even
#then print out the private IP address followed by (+1) the 
#advertisting count that has been accumulated
for x in range(len(privIP_list)):
   if x % 2 == 0:
      #print("The IP address "),
      checkIP=privIP_list[x]
      host_name,alias,addreslist = lookup(checkIP)
      print(host_name),
      print(privIP_list[x]),
      print("has "),
      print(privIP_list[x+1]),
      print("advertising hits")

 #  adver.close()
    #for words in line:
    #  if words.find('adnxs.com'.lower()) != -1:
    #     count += 1
#print("\nYour search value of '%s' appears %s times in this file" % ('adnxs.com', count))
