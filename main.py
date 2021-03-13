#!/usr/bin/env python3

import requests
import json
import os
import yaml
from terminaltables import AsciiTable
from termcolor import colored
from bs4 import BeautifulSoup

from detect_phishing import detect


suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'
valid_domains_yaml = os.path.dirname(os.path.realpath(__file__))+'/valid_domains.yaml'
dataset_yaml = os.path.dirname(os.path.realpath(__file__))+'/dataset.yaml'


def get_cert_info(hostname):
	print('\tTry to get certificate... ', end='')
	try:
		url_api = "https://api.blupig.net/certificate-info/validate"
		headers = {"x-validate-host" : hostname} 

		r = requests.get(url_api, headers=headers)
		cert_info_json = r.text
		cert_info = json.loads(cert_info_json)
		print("OK!")
		return cert_info
	except:
		print('\n\t{}Unable to get certificate info for {}.'
			  ' Failed to establish a connection with server API: {}'.format(colored('[ERR]', attrs=['bold']), hostname, r))
		return None

def get_protocol(hostname):
	print('\tTry to connect... ', end='')
	try:
		r = requests.get("http://"+hostname)
		r = r.url
		secure = r.startswith('https')
		protocol = 'https' if secure else 'http'
		print("OK! Protocol: "+protocol)
		return protocol,r
	except:
		return None,None

def get_html(hostname):
	print('\tTry to get HTML... ', end='')
	try:
		r = requests.get("http://"+hostname).text
		if r == '': 
			print("Failed! Unable to get HTML content!")
			return None
		else:
			html_text = BeautifulSoup(r, "html.parser")
			print("OK!")
			return html_text
	except:
		print('\n\t{}Unable to get HTML content for {}.'
			  ' Failed to establish a connection with: {}'.format(colored('[ERR]', attrs=['bold']), hostname, hostname))

###

if __name__ == '__main__':
	with open(dataset_yaml, 'r') as f:
		dataset = yaml.safe_load(f)

	with open(suspicious_yaml, 'r') as f:
		suspicious = yaml.safe_load(f)

	with open(valid_domains_yaml, 'r') as f:
		valid_domains = yaml.safe_load(f)

	print('Start hostname analysis:')

	total = 0
	TP = 0
	TN = 0
	FP = 0
	FN = 0

	for hostname in dataset['data']:
		score = 0
		err = False

		print('hostname: \033[1m'+hostname+'\033[0m')

		res = get_protocol(hostname)
		
		protocol = res[0]
		url = res[1]

		if protocol == "https":
			cert_info = get_cert_info(hostname)
			html = get_html(hostname)
			score += detect(html, cert_info, url, hostname, suspicious, valid_domains)

		elif protocol == "http":
			score += 10
			html = get_html(hostname)
			score += detect(html=html, url=url, hostname=hostname, sus=suspicious, valid=valid_domains)

		else:
			print('\n\t{}Failed to establish a connection with: {}'.format(colored('[ERR]', attrs=['bold']), hostname))
			err = True

		if not err:
			total += 1

			if score >= 100:
				print('\t{} {}'.format(colored('[SCORE]', attrs=['bold']), colored(score, 'red', attrs=['bold'])))
			elif score >= 80:
				print('\t{} {}'.format(colored('[SCORE]', attrs=['bold']), colored(score, 'yellow', attrs=['bold'])))
			elif score >= 60:
				print('\t{} {}'.format(colored('[SCORE]', attrs=['bold']), colored(score, 'yellow', attrs=['bold'])))
			else:
				print('\t{} {}'.format(colored('[SCORE]', attrs=['bold']), colored(score, 'green', attrs=['bold'])))

			predict = 0
			if score >= 60:
				predict = 1

			if predict == 0 and dataset['data'][hostname] == 0:
				TN += 1
			elif predict == 0 and dataset['data'][hostname] == 1:
				FN += 1
			elif predict == 1 and dataset['data'][hostname] == 1:
				TP += 1
			else:
				FP += 1

	#endfor
	print('\n')
	table_data = [
	    [' TOT:\n{}'.format(total),'Actual:\nPOS', 'Actual: \nNEG'],
	    ['Predicted:\nPOS',   TP,            FP],
	    ['Predicted:\nNEG',   FN,            TN]
	    
	]
	table = AsciiTable(table_data)
	table.inner_row_border = True
	table.justify_columns[0] = 'center'
	table.justify_columns[1] = 'center'
	table.justify_columns[2] = 'center'
	print('{}'.format(table.table))





