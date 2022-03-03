#!/usr/bin/env python3

import io
import re
import sys
import requests
import urllib3
import paramiko

from argparse import ArgumentParser, Namespace
from tabulate import tabulate
from scp import SCPClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RE_REPLACE_MULTIBLANKS = re.compile(r'\s+')
RE_REPLACE_INVALIDCHARS = re.compile(r'[^a-zA-Z0-9\-\_]')
ALIAS_CONF_FILEPATH = '/run/dnsmasq.conf.d/alias.conf'

def getNetworks(session: requests.Session, args: Namespace):
	response = session.get(f'{args.baseurl}/proxy/network/api/s/{args.site}/rest/networkconf', verify=False)
	response.raise_for_status()
	return response.json()['data']

def getClients(session: requests.Session, args: Namespace):
	response = session.get(f'{args.baseurl}/proxy/network/api/s/{args.site}/list/user', verify=False)
	response.raise_for_status()
	return response.json()['data']

def resolveAliases(alias: str, hostname: str):

	alias = alias.strip().rstrip(')').replace('(', ',') 					# sanitize the raw string
	alias = RE_REPLACE_MULTIBLANKS.sub(' ', alias)							# compress multi blanks
	
	aliases = [a.strip().replace(' ', '-') for a in alias.split(',')]		# trim and replace space with dash on each alias
	aliases = [RE_REPLACE_INVALIDCHARS.sub('', a) for a in aliases]			# strip out invalid characters on each alias
	
	# final filter for alias names: strip out NONE or EMPTY or equal to HOSTNAME
	validAlias = lambda a: not( a == None or a == '' or str(a).casefold() == hostname.casefold())

	return list(filter(validAlias, aliases))

def generateAliasMap(networks: dict, clients: dict):

	hostnameBlacklist=['', 'localhost']
	networkMap = set()
	aliasMap = {}

	for n in networks:
		if 'domain_name' in n and n['domain_name']: networkMap.add(n['domain_name'])

	if not(networkMap):
		networkMap.add('home.arpa')

	for c in clients:
		if 'name' in c and 'hostname' in c and str(c['hostname']).lower() not in hostnameBlacklist:
			aliases = resolveAliases(str(c['name']), str(c['hostname'])) 
			for a in [f'{a}.{n}' for a in aliases for n in networkMap]:
				aliasMap[a] = str(c['hostname'])

	return aliasMap

def main():

	parser = ArgumentParser()
	parser.add_argument('-b', '--baseurl', type=str, default="https://192.168.0.1:443", help='The site\'s base URL. Defaults to: "https://192.168.0.1:443"')
	parser.add_argument('-u', '--username', type=str, default="root", help='Your user\'s username. Defaults to: "root"')
	parser.add_argument('-p', '--password', type=str, default="ubnt", help='Your user\'s password. Defaults to: "ubnt"')
	parser.add_argument('-s', '--site', type=str, default="default", help='The name of your unifi site. Defaults to: "default"')
	parser.add_argument('-su', '--ssh_username', type=str, default="root", help='Your UDM\'s SSH username. Defaults to: "root"')
	parser.add_argument('-sp', '--ssh_password', type=str, default="ubnt", help='Your UDM\'s SSH password. Defaults to: "ubnt"')
	parser.add_argument('-sa', '--ssh_address', type=str, default="192.168.0.1", help='Your UDM\'s SSH address. Defaults to: "192.168.0.1"')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. May be specified multiple times for increased verbosity.')
	
	args = parser.parse_args()
	session = requests.Session()

	if args.verbose: print('Logging into the controller...')
	response = session.post(f'{args.baseurl}/api/auth/login', json={'username': args.username, 'password': args.password}, verify=False)
	response.raise_for_status()

	if args.verbose: print('Fetching network information ...')
	networks = getNetworks(session, args)

	if args.verbose: print('Fetching client information ...')
	clients = getClients(session, args)

	if args.verbose: print('Generating alias map ...')
	aliasMap = generateAliasMap(networks, clients)

	overview = tabulate(
		[[k, v] for k, v in aliasMap.items()], 
		headers=['Alias', 'Hostname'],
		tablefmt="github")

	print(f'\n{overview}\n')

	if args.verbose: print('Creating an SSH session...')
	with paramiko.SSHClient() as ssh:
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		ssh.connect(hostname=args.ssh_address,username=args.ssh_username,password=args.ssh_password)

		if args.verbose: print('Pushing new alias.conf file...')
		with SCPClient(ssh.get_transport()) as scp:
			with io.BytesIO() as buffer:
				for k, v in aliasMap.items():
					buffer.write(f'cname={k},{v}\n'.encode('utf-8'))
				buffer.seek(0)
				scp.putfo(buffer, ALIAS_CONF_FILEPATH)

		if args.verbose: print('Restarting dnsmasq service...')
		ssh.exec_command("""killall dnsmasq""")

	sys.exit(0)

if __name__ == '__main__': main()