#!/usr/bin/python

#######################################################################
#
# Analysing Apache log files to get some general insights about the  accessablility of a web application
#
# Author: Ahmed ElShafei [elshafei.ah@gmail.com]
#
# NOTE: consider changing the constants in the conf.py file
#
# Description:
# This is a Python script is meant to fetch Apache access log files of an enviroment to get
# an overall staus of web accessability of an online application. It can be run as a cronjob, also, it can be run manually 
# by running ./al2r.py .
#
# Change log:
# 08.03.2016	Ahmed ElShafei	Script re-created
#
#######################################################################


#Let's Play

##################################################
# Section 00. Importing Python Libraries 		 #
##################################################

import sys
import os
import time
import shutil
import re
import datetime
import collections
import operator
import pprint
import csv
import math
import commands
import smtplib
import getpass
import socket

##################################################
# Section 01. DEFINIONS 				   	     #
##################################################

# for modularity, configuration is set in seprate file and other helper classes as well, We're going to import it as  modules
from conf import *
from ssh import *
from helpers import *
from ua_parser import user_agent_parser


# computing reference time to discard log lines older than that time based on PERIOD value
START_DATE = datetime.datetime.now()
period_args = ''.join(conf.PERIOD.split())
period_measure = period_args[-1].lower()
period_val = period_args[0:-1]
if not period_measure in ('h', 'd', 'm'):
	print('\t' + bcolors.FAIL + 'Not valid PERIOD measure unit, please use either m for minutes, h for hours or d for days' + bcolors.ENDC)
	exit(1)
#check if period value is valid
try:
	period_val = int(period_val)
	if period_val < 1 :
		print('\t' + bcolors.FAIL + 'Not valid PERIOD value, please set positive number value ' + bcolors.ENDC)
		exit(1)
except Exception:
	print('\t' + bcolors.FAIL + 'Not valid PERIOD value, please set value in numbers' + bcolors.ENDC)
	exit(1)

if period_measure == 'h':
	dt_ref = START_DATE - datetime.timedelta(hours=period_val)
elif period_measure == 'm':
	dt_ref = START_DATE - datetime.timedelta(minutes=period_val)
else:
	dt_ref = START_DATE - datetime.timedelta(days=period_val)

#print dt_ref


##################################################
# Section 02. INTIALIZATION 				     #
##################################################


print(' * Intializing ....\n')



# Check if the Tempraroy directory exist, otherwise create it
print(' * checking temporary directory ....')
if not os.path.exists(TEMP_DIR):
	print('\t Tempraroy directory not found, creating into ' + TEMP_DIR)
	os.makedirs(TEMP_DIR)
	print('\t .. ' + bcolors.OKGREEN + 'DONE' + bcolors.ENDC + '\n')
else:
	print('\t Tempraroy directory at ' + TEMP_DIR + ' already exists\n')



# check whether log files to be remotely searched or locally
print(' * check whether log files to be remotely searched or locally')
if REMOTE:
	print('\t Files to be searched remotely\n')
	#check if Hosts is SSH accessable
	sshSessions = []	# a list of SSH sessions to be intitiated
	print(' * check if Hosts is accessable normally !')
	for hostname in HOSTNAMES:
		sshSession = SSH(hostname, '', USERNAME, 22)
		sshSessions.append( sshSession )
		result = sshSession.cmd('echo Ok')
		if 'Ok' in result:
			print('\t ' + hostname + ' can be accessed successfully')
		else:
			print('\t' + 'Error accessing ' + hostname )
			exit(1)
	print('\n')
else:
	print('\t Files to be searched locally\n')


# getting log files into the temporary directory
if REMOTE:
	print(' * getting log files from remote servers')
	for sshSession in sshSessions:
		#getting the list of files to be copied from the remote log directory
		#generating the placeholder of time frame in oder to be append in find command
		period_placeholder = calculate_period()
		logfiles = sshSession.cmd('find ' + DIRECTORY.replace(" ", "") + '/*  ' + period_placeholder + ' | grep ' + COMMON_LOGFILE_NAME)
		logfiles_list = logfiles.split()
		print('\t' + str(len(logfiles_list)) + ' log files found in ' + sshSession.ip + '\n')
		if len(logfiles_list):
			for logfile in logfiles_list:
				scp_output = sshSession.pull(logfile, TEMP_DIR)
				if '100%' in scp_output:
					print('\t' + logfile + ' successfully copied from ' + sshSession.ip + ' to ' + TEMP_DIR + '\n')
				else:
					print('\t Error coping' + logfile + ' from ' + sshSession.ip + '\n')
					exit(1)

	print('\t ... DONE')
	print('\n')

else:
	print(' * getting files from local server')
	#calculating second based on PERIOD configuration
	period_placeholder = calculate_period()
	past = time.time() - period_placeholder
	logfiles = []
	for p, ds, fs in os.walk(DIRECTORY):
	    for fn in fs:
	        filepath = os.path.join(p, fn)
	        if os.path.getmtime(filepath) >= past and COMMON_LOGFILE_NAME in filepath :
	            logfiles.append(filepath)


	print ('\t ' + str(len(logfiles)) + ' files found in the local directory ')

	for logfile in logfiles:
		shutil.copy2(logfile, TEMP_DIR)
		print ('\t' + logfile + ' copied to ' + TEMP_DIR)
	print('\n')


#loading IP Gelolaction DB
ip_geo_db_f = open(IP_COUNTRY_DB)
csvReader = csv.reader(ip_geo_db_f)
ip_geo_db_data = list(csvReader)
#print(ip_geo_db_data[0])

##################################################
# Section 03. Reading logfiles 				     #
##################################################


TOKEN_POS = {} #dictionary of apache access log tokens position in log line based on LOGFORMAT value
LFS = LOGFORMAT.split('\"')

#getting token positions in log lines
for i,v in TOKEN_DICT.items():
	#print( i )

	TOKEN_POS.update({i : [LFS.index(s) for s in LFS if i in s]})
	if i == LFS[TOKEN_POS[i][0]]:
		TOKEN_POS[i].append(-1)
	else:
		TOKEN_POS[i].append(LFS[TOKEN_POS[i][0]].split().index(i))
	#print( TOKEN_POS[i] )


logs = [] #this list will hold the log lines


print(' * reading log files ..')
#loading log line from log giles
for log_file in os.listdir(TEMP_DIR):
	#print log_file
	log_file_path = os.path.join(TEMP_DIR, log_file)
	if os.path.isfile(log_file_path):
		for line in open(log_file_path, 'r').readlines():
			#print line
			if len(line) > 0:
				LLS = re.sub(r'\[.+?\]', lambda x:x.group().replace(" ","_"), line.rstrip()).split('"')
				line_details = {}
				for i,v in TOKEN_POS.items():
					if v[1] == -1:
						line_details.update({TOKEN_DICT[i]: LLS[v[0]]})
					else:
						line_details.update({TOKEN_DICT[i]: LLS[v[0]].split()[v[1]]})
				line_details['time_stamp'] = time.strptime(line_details['time_stamp'][1:-1].split('_')[0], '%d/%b/%Y:%H:%M:%S')
				line_details.update({'user_agent_details' : user_agent_parser.Parse(line_details['user_agent']) })
				line_details.update({'log_file': log_file})
				#filter odd log line. ex: 84.3.41.146 - - [03/Feb/2016:12:00:14 +0100] "-" 408 - "-" "-" 7
				if datetime.datetime(*line_details['time_stamp'][0:6]) > dt_ref and  not ( line_details['user_agent'] == '-'  and  line_details['request_line'] == '-' and line_details['response_size'] == '-'):
					logs.append(line_details)

#pprint.pprint( logs[0] )

#print( len(logs) )

print ('\t ' + str(len(logs)) + ' log lines loaded ..\n')





##################################################
# Section 04. Processing logs 				     #
##################################################


print(' * processing logs ..')


for log in logs:

	#counting status codes occurrence 
	if log['status'] in HTTP_STATUS_CODE_OCCUR.keys():
 		HTTP_STATUS_CODE_OCCUR[log['status']] += 1

 	#getting most referring URLs
	if log['referer_url'] !='-':
	 	if log['referer_url'] in  MOST_REFERING_URLS.keys():
	 		MOST_REFERING_URLS[log['referer_url']] += 1
	 	else:
	 		MOST_REFERING_URLS.update({log['referer_url'] : 1 })

 	#calculating most requested ips
	if log['remote_host'] in MOST_REQUESTING_IPs.keys():
 		MOST_REQUESTING_IPs[log['remote_host']] += 1
	else:
 		MOST_REQUESTING_IPs.update({ log['remote_host'] : 1 })

 	#calculating most requested URLS
	if log['request_line'].split()[1] in MOST_REQUESTING_URLS.keys():
 		MOST_REQUESTING_URLS[log['request_line'].split()[1]] += 1
	else:
 		MOST_REQUESTING_URLS.update({ log['request_line'].split()[1] : 1 })

 	# getting longest  response size and Time taken to server the URL
	if  log['request_line'].split()[1] in LONGEST_URL_RESPONSE_TIME.keys():
 		if int(log['response_time']) > LONGEST_URL_RESPONSE_TIME[log['request_line'].split()[1]]:
 			LONGEST_URL_RESPONSE_TIME[log['request_line'].split()[1]] = int(log['response_time'])
	else:
 		LONGEST_URL_RESPONSE_TIME.update({ log['request_line'].split()[1] : int(log['response_time']) })

 	# getting largest response size
	if log['response_size'] != '-':
	 	if log['request_line'].split()[1] in LARGEST_URL_RESPONSE_SIZE.keys():
	 		if int(log['response_size']) > LARGEST_URL_RESPONSE_SIZE[log['request_line'].split()[1]]:
	 			LARGEST_URL_RESPONSE_SIZE[log['request_line'].split()[1]] = int(log['response_size'])
	 	else:
	 		LARGEST_URL_RESPONSE_SIZE.update({ log['request_line'].split()[1] : int(log['response_size']) })

	#getting  Most reuesting Clients
	if log['user_agent_details']['user_agent']['family'] != 'Other':
		if log['user_agent_details']['user_agent']['family'] in MOST_REQUESTING_CLIENTS.keys():
			MOST_REQUESTING_CLIENTS[log['user_agent_details']['user_agent']['family']] += 1
		else:
			MOST_REQUESTING_CLIENTS.update({ log['user_agent_details']['user_agent']['family'] : 1 })
	else:
		if log['user_agent_details']['string'].split()[0].split('/')[0] in MOST_REQUESTING_CLIENTS.keys():
			MOST_REQUESTING_CLIENTS[log['user_agent_details']['string'].split()[0].split('/')[0]] += 1
		else:
			MOST_REQUESTING_CLIENTS.update({ log['user_agent_details']['string'].split()[0].split('/')[0] : 1})

	#getting Most reuesting OS
	if log['user_agent_details']['os']['family'] != 'Other':
		if log['user_agent_details']['os']['family'] in MOST_REQUESTING_OS.keys():
			MOST_REQUESTING_OS[log['user_agent_details']['os']['family']] += 1
		else:
			MOST_REQUESTING_OS.update({ log['user_agent_details']['os']['family'] : 1 })
	else:
		if len(log['user_agent_details']['string'].split()) > 2:
			log_ua_os = log['user_agent_details']['string'].split()[1][1:-1]
			if log_ua_os in MOST_REQUESTING_OS.keys():
				MOST_REQUESTING_OS[log_ua_os] += 1
			else:
				MOST_REQUESTING_OS.update({ log_ua_os : 1})

 	#count HTTP methods
	log_method = log['request_line'].split()[0]
	if log_method in HTTP_METHODS_COUNT.keys():
 		HTTP_METHODS_COUNT[log_method] += 1

#Calaculating most requesting counteries
for k,v in MOST_REQUESTING_IPs.items():
	#print(k)
	ip_vals = k.split('.')
	ip_number = int(ip_vals[0]) * 16777216 + int(ip_vals[1]) * 65536 + int(ip_vals[2]) * 256 + int(ip_vals[3])
	for ip_range in ip_geo_db_data:
		if ip_number >= int(ip_range[0]) and ip_number <= int(ip_range[1]):
			country_val = ip_range[3] + ' (' + ip_range[2] + ')'
			break
	if country_val in TOP_REQUESTING_COUNTERIES.keys():
		TOP_REQUESTING_COUNTERIES[country_val] += v
	else:
		TOP_REQUESTING_COUNTERIES.update({country_val : v })


print('\t Peocessing done, formatting for printing ..\n\n')
##################################################
# Section 05. Report formatting 				 #
##################################################

#
#test
#

if SEND_EMAIL:
	__HTTP_STATUS_CODES_ROWS = '' 
	__HTTP_REQUEST_TYPES_ROWS = ''
	__TOP_REQUESTING_IPS_ROWS = ''
	__TOP_REQUESTING_CLIENTS_ROWS = ''
	__TOP_REQUESTING_OSS_ROWS = ''
	__TOP_REQUESTING_COUNTRIES_ROWS = ''
	__TOP_REQUESTED_URLS_ROWS = ''
	__TOP_REFERER_ULS_ROWS = ''
	__LONGEST_RESPONSE_TIME_URLS_ROWS = ''
	__LARGEST_RESPONSE_SIZE_URLS_ROWS = ''

	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__ENVIRONMENT', ENVIRONMENT)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__PERIOD_FRAME', PERIOD )
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__START_DATE', START_DATE.strftime("%Y-%m-%d %H:%M:%S"))
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__FROM_EMAIL', getpass.getuser() + '@' +  socket.gethostname())
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TO_EMAILS', ', '.join(TO_EMAILS) )
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__SUBJECT', ENVIRONMENT + ' | a2lr ')



#printing http status
print(bcolors.HEADER + 'HHTP Status codes' + bcolors.ENDC)
for i,v in sorted(HTTP_STATUS_CODE_OCCUR.items(), key=operator.itemgetter(0)):
#for i,v in collections.OrderedDict(sorted(HTTP_STATUS_CODE_OCCUR.items())).items():
	if v > 0:
		print( '   ' + i + ' : ' + str(v) )
		if SEND_EMAIL:
			__HTTP_STATUS_CODES_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)


print('\n')


#printing http methods
print(bcolors.HEADER + 'HHTP Methods' + bcolors.ENDC)
for i,v in HTTP_METHODS_COUNT.items():
	if v > 0:
		print( '   ' +  i + ' : ' + str(v) )
		if SEND_EMAIL:
			__HTTP_REQUEST_TYPES_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')



#most requesting ips
print(bcolors.HEADER + 'Most Requesting IPs' + bcolors.ENDC)

for i,v in sorted(MOST_REQUESTING_IPs.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	print( '   ' + i  + ' : ' + str(v) + ' times' )
	if SEND_EMAIL:
			__TOP_REQUESTING_IPS_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')


#printing most requesting clients 
print(bcolors.HEADER + 'Most requesting clients' + bcolors.ENDC)

for i,v in sorted(MOST_REQUESTING_CLIENTS.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	if i != '-':
		print( '   ' + i  + ' : ' + str(v) + ' times' )
		if SEND_EMAIL:
				__TOP_REQUESTING_CLIENTS_ROWS += ('<tr>\n'
											  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
											   + i + 
											   ' </td>\n'
											   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
											   + str(v) + 
											   ' </td>\n'
											   '</tr>\n'
											)

print('\n')

#printing most requesting OSs 
print(bcolors.HEADER + 'Most Requesting OSs' + bcolors.ENDC)
for i,v in sorted(MOST_REQUESTING_OS.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	print( '   ' + i  + ' : ' + str(v) + ' times' )
	if SEND_EMAIL:
			__TOP_REQUESTING_OSS_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')

#printing Top requesting Countries 
print(bcolors.HEADER + 'Top requesting Countries' + bcolors.ENDC)
for i,v in sorted(TOP_REQUESTING_COUNTERIES.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	print( '   ' + i  + ' : ' + str(v) + ' times' )
	if SEND_EMAIL:
			__TOP_REQUESTING_COUNTRIES_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')

#printing most requesting URLS
print(bcolors.HEADER + 'Most requesting URLs' + bcolors.ENDC)

for i,v in sorted(MOST_REQUESTING_URLS.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	print( '   ' + i  + ' : ' + str(v) + ' times' )
	if SEND_EMAIL:
			__TOP_REQUESTED_URLS_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')

#printing most referering URLs
print(bcolors.HEADER + 'Most referering URLs' + bcolors.ENDC)
for i,v in sorted(MOST_REFERING_URLS.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	print( '   ' + i  + ' : ' + str(v) + ' times' )
	if SEND_EMAIL:
			__TOP_REFERER_ULS_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + str(v) + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')

#printing Longest resonse time
print(bcolors.HEADER + 'Longest respone time' + bcolors.ENDC)
for i,v in sorted(LONGEST_URL_RESPONSE_TIME.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	if v > 0:
		log_time_string = ''
		if v / 1000000 > 60 :
			log_time_string = str(v / 60000000  ) + ' mins'
			arb = (v  % 60000000) / 1000000
			if arb > 0 :
				log_time_string += ' , ' + str(arb) + ' secs'
		else:
			log_time_string = str( v / 1000000)  + ' seconds '

		print( '   ' + i + ' : ' + log_time_string)
		if SEND_EMAIL:
			__LONGEST_RESPONSE_TIME_URLS_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + i + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + log_time_string + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')

#printing Largest resonse size
print(bcolors.HEADER + 'Largest respone size' + bcolors.ENDC)

for k,v in sorted(LARGEST_URL_RESPONSE_SIZE.items(), key=operator.itemgetter(1), reverse=True)[:10]:
	if v > 0:
		v = v / 1024
		size_name = ("KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
		i = int(math.floor(math.log(v,1024)))
		p = math.pow(1024,i)
		s = round(v/p,2)
		response_size_str =  str(s) + str(size_name[i])

		print( '   ' + k + ' : ' + response_size_str )
		if SEND_EMAIL:
			__LARGEST_RESPONSE_SIZE_URLS_ROWS += ('<tr>\n'
										  '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + k + 
										   ' </td>\n'
										   '<td style="background-color: #A1C6DF; color: black;min-width:50px;padding:5px">\n'
										   + response_size_str + 
										   ' </td>\n'
										   '</tr>\n'
										)

print('\n')




if SEND_EMAIL:
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__HTTP_STATUS_CODES_ROWS', __HTTP_STATUS_CODES_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__HTTP_REQUEST_TYPES_ROWS', __HTTP_REQUEST_TYPES_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TOP_REQUESTING_IPS_ROWS', __TOP_REQUESTING_IPS_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TOP_REQUESTING_CLIENTS_ROWS', __TOP_REQUESTING_CLIENTS_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TOP_REQUESTING_OSS_ROWS', __TOP_REQUESTING_OSS_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TOP_REQUESTING_COUNTRIES_ROWS', __TOP_REQUESTING_COUNTRIES_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TOP_REQUESTED_URLS_ROWS', __TOP_REQUESTED_URLS_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__TOP_REFERER_ULS_ROWS', __TOP_REFERER_ULS_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__LONGEST_RESPONSE_TIME_URLS_ROWS', __LONGEST_RESPONSE_TIME_URLS_ROWS)
	EMAIL_HTML_TEMPLATE =  EMAIL_HTML_TEMPLATE.replace('__LARGEST_RESPONSE_SIZE_URLS_ROWS', __LARGEST_RESPONSE_SIZE_URLS_ROWS)
	
	#f = open('DATA/email.html', 'w')
	#f.write(EMAIL_HTML_TEMPLATE)
	#f.close()
	print('\n\n * Sending email report ..')
	try:
		smtpObj = smtplib.SMTP('localhost')
		smtpObj.sendmail( 'test@test.com', TO_EMAILS , EMAIL_HTML_TEMPLATE)         
		print " \t Successfully sent email .."
	except SMTPException:
		print "Error: unable to send email"

##################################################
# Section 02. Finazlization 				     #
##################################################

#remove temp log files
for file in os.listdir(TEMP_DIR):
    file_path = os.path.join(TEMP_DIR, file)
    try:
        if os.path.isfile(file_path):
            os.unlink(file_path)
        #elif os.path.isdir(file_path): shutil.rmtree(file_path)
    except Exception , e:
        print(e)


