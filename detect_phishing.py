import math
import re
import tldextract
from tld import get_tld
from Levenshtein import distance
from bs4 import BeautifulSoup

suspicious = ''
valid_domains = ''

##CERT

def is_issued_from_free_ca(cert_info):
	if cert_info['issuer_organization'] == "Let's Encrypt":
		return 1
	else:
		return 0


def is_DV_certificate(cert_info):
	if cert_info['validation_result_short'] == 'DV':
		return 1
	else:
		return 0

##DOMAIN

def ends_with_sus_tld(hostname):
	count = 0
	for t in suspicious['tlds']:
		if hostname.endswith(t):
			count += 1
	return count

def entropy(hostname):
	prob = [ float(hostname.count(c)) / len(hostname) for c in dict.fromkeys(list(hostname)) ]
	entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
	return entropy

def has_fake_tld(hostname):
	res = 0
	words = re.split("\W+", hostname)

	if words[0] in ['com', 'net', 'org']:
	    res = 1

	return res

def has_sus_keywords(hostname):
	score = 0
	for word in suspicious['keywords']:
	    if word in hostname:
	        score += suspicious['keywords'][word]
	return score

def levenshtein_distance(hostname):
	score = 0
	words_in_domain = re.split("\W+", hostname)
	# Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
	for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
	    # Removing too generic keywords (ie. mail.domain.com)
	    for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
	        if distance(str(word), str(key)) == 1:
	            score += 70
	return score

def lot_of_dash(hostname):
	count = 0
	if 'xn--' not in hostname and hostname.count('-') >= 4:
	    count += hostname.count('-')
	return count

def nested_subdomains(hostname):
	count = 0
	if hostname.count('.') >= 3:
	    count += hostname.count('.')
	return count

##URL

def is_long_url(url):
	return 1 if len(url) > 75 else -1

def is_ip_url(url):
	res = re.match(r"^http(s{0,1})://\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}(:|/).*$", url)
	return 1 if res != None else -1

def is_tiny_url(url):
	return -1 if len(url) > 20 else 1

def contains_at(url):
	return -1 if re.match("@", url) != None else 1

def is_redirecting_url(url):
	res = re.match(r"^http.*:(//).*(//).*", url)
	return 1 if res != None else -1

def is_illegal_https_url(url):
	pattern = re.compile("//")
	res = pattern.search(url)

	url = url[res.span()[1]:]

	pattern = re.compile("https")
	res = pattern.search(url)
	
	return 1 if res != None else -1
	
def is_multidomain_url(url):
	res = re.match(r"^http.*://(.*)", url).groups()
	res = re.split("/", res[0])
	dot_count = res[0].count(".")
	return -1 if dot_count < 5 else 1

##CONTENT

def is_mailto_available(html):
	res = html.find_all(href=re.compile("mailto"))
	return 1 if len(res) > 0 else -1

def is_iframe_present(html):
	res = html.find_all('iframe')
	return 1 if len(res) > 0 else -1

def is_img_from_different_domain(html,url):
	total_img = len(html.find_all('img'))
	img_identical_domain = get_identical_count(html, url, 'img')
	if total_img > 0:
		if (total_img - img_identical_domain)/total_img < 0.22:
			return -1
		elif (total_img - img_identical_domain)/total_img >= 0.22 and (total_img - img_identical_domain)/total_img <= 0.61:
			return 0
		else:
			return 1
	else:
		return -1

def is_favicon_domain_unidentical(html,url):
	favicon = html.find_all(rel=re.compile("(shortcut icon|SHORTCUT ICON)"))
	url_domain = re.search(r'^http.{0,1}://[^/#:]+(/|#|:)', url)######
	url_domain = url[0:url_domain.span()[1]-1]

	if len(favicon) > 0:
		url_favicon = favicon[0].get('href')
		favicon_domain = re.search(r'[a-zA-Z]/', url_favicon)
		if favicon_domain != None:
			favicon_domain = url_favicon[0:favicon_domain.span()[1]-1]
			if url_domain == favicon_domain:
				return -1
			else:
				return 1
		else:
			return -1
	else:
		return -1


def is_anchor_from_different_domain(html,url):
	total_anchor = len(html.find_all('a'))
	anchor_identical_domain = get_identical_count(html, url, 'a')
	if total_anchor > 0:
		if (total_anchor - anchor_identical_domain)/total_anchor < 0.31:
			return -1
		elif (total_anchor - anchor_identical_domain)/total_anchor >= 0.31 and (total_anchor - anchor_identical_domain)/total_anchor <= 0.67:
			return 0
		else:
			return 1
	else:
		return -1

def is_scriptlink_from_different_domain(html,url):
	total_script_link = len(html.find_all('script')) + len(html.find_all('link'))
	identical_domain_script_link = get_identical_count(html, url, 'script') + get_identical_count(html, url, 'link')
	if total_script_link > 0:
		if (total_script_link - identical_domain_script_link)/total_script_link < 0.17:
			return -1
		elif (total_script_link - identical_domain_script_link)/total_script_link >= 0.17 and (total_script_link - identical_domain_script_link)/total_script_link <= 0.81:
			return 0
		else:
			return 1
	else:
		return -1


def is_form_action_invalid(html, url):
	total_form = len(html.find_all('form'))
	form_identical_domain = get_identical_count(html, url, 'form')
	
	all_form = html.find_all('form')
	form_action_blank = 0
	form_action = 0

	for f in all_form:
		action = f.get('action')
		if action != None:
			form_action += 1
			if action == '':
				form_action_blank += 1

	if form_action <= 0:
		return -1
	elif total_form != form_identical_domain:
		return 0
	elif form_action_blank > 0:
		return 1
	else:
		return -1



def get_identical_count(html, url, tag):
	node_list = html.find_all(tag)
	url_domain = re.search(r'^http.{0,1}://[^/#:]+(/|#|:)', url)#####
	url_domain = url[0:url_domain.span()[1]-1]
	count = 0

	if tag == "img" or tag == "script":
		for node in node_list:
			node_src = node.get('src')
			if node_src != None and node_src != '':
				node_src_domain = re.search(r'[a-zA-Z]/', node_src)
				if node_src_domain != None:
					node_src_domain = node_src[0:node_src_domain.span()[1]-1]
					if node_src_domain == url_domain:
						count += 1

	elif tag == "form":
		for node in node_list:
			node_src = node.get('action')
			if node_src != None and node_src != '':
				node_src_domain = re.search(r'[a-zA-Z]/', node_src)
				if node_src_domain != None:
					node_src_domain = node_src[0:node_src_domain.span()[1]-1]
					if node_src_domain == url_domain:
						count += 1

	else:
		for node in node_list:
			node_src = node.get('href')
			if node_src != None and node_src != '':
				node_src_domain = re.search(r'[a-zA-Z]/', node_src)
				if node_src_domain != None:
					node_src_domain = node_src[0:node_src_domain.span()[1]-1]
					if node_src_domain == url_domain:
						count += 1
	
	return count

##AUX

def remove_wildcard(hostname):
	if hostname.startswith('*.'):
	    hostname = hostname[2:]
	return hostname

def remove_tld(hostname):
	try:
	    res = get_tld(hostname, as_object=True, fail_silently=True, fix_protocol=True)
	    hostname= '.'.join([res.subdomain, res.domain])
	except Exception:
	    pass

	return hostname

def is_valid_domain(url):
	res = tldextract.extract(url)
	domain = '.'.join([res.domain, res.suffix])
	
	for d in valid_domains['domains']:
		if domain == d:
			return True
	return False

##SCORE

def score_cert(cert_info):
	score = 0
	
	score += is_issued_from_free_ca(cert_info)*10
	score += is_DV_certificate(cert_info)*10
	#print('\t Score CERT: {}'.format(score))

	return score

def score_domain(hostname):
	score = 0
	score += ends_with_sus_tld(hostname)*20

	hostname = remove_wildcard(hostname)
	hostname = remove_tld(hostname)

	score += int(round(entropy(hostname)*10))
	score += has_fake_tld(hostname)*10
	score += has_sus_keywords(hostname)
	score += levenshtein_distance(hostname)
	score += lot_of_dash(hostname)*3
	score += nested_subdomains(hostname)*3
	#print('\t Score DOMAIN: {}'.format(score))

	return score

def score_url(url):
	score = 0

	score += is_ip_url(url)*(3.333)
	score += is_long_url(url)*(-1.112)#-
	score += is_tiny_url(url)*(-7.778)#-
	score += contains_at(url)*(1.110)
	score += is_redirecting_url(url)*(3.894)
	score += is_illegal_https_url(url)*(-0.0006)#-
	score += is_multidomain_url(url)*(4.443)
	#print('\t Score URL: {}'.format(score))

	return score

def score_html(html, url):
	score = 0
	
	score += is_mailto_available(html)*(0.557)
	score += is_iframe_present(html)*(-1.666)#-
	score += is_img_from_different_domain(html, url)*(3.332)
	score += is_favicon_domain_unidentical(html, url)*(-2.779)#-
	score += is_anchor_from_different_domain(html, url)*(26.664)
	score += is_scriptlink_from_different_domain(html, url)*(6.667)
	score += is_form_action_invalid(html, url)*(5.554)
	#print('\t Score HTML: {}'.format(score))

	return score

###################DETECTION#######################

def detect(html='', cert_info='', url='', hostname='', sus='', valid=''):
	print('\tDetection started...')

	global suspicious
	global valid_domains

	if sus != '':
		suspicious = sus
	if valid != '':
		valid_domains = valid

	if is_valid_domain(url): return 0
	
	score = 0

	if (html != '' and html != None) and (cert_info != '' and cert_info != None):
		score += score_cert(cert_info)
		score += score_domain(hostname)
		score += score_url(url)
		score += score_html(html, url)
	elif (html != '' and html != None) and (cert_info == '' or cert_info == None):
		score += score_domain(hostname)
		score += score_url(url)
		score += score_html(html, url)
	elif (html == '' or html == None) and (cert_info != '' and cert_info != None):
		score += score_cert(cert_info)
		score += score_domain(hostname)
		score += score_url(url)
	else:
		score += score_domain(hostname)
		score += score_url(url)

	#print(int(round(score)))
	return int(round(score))




