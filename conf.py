## in this section some basic definition is set as follows :

#Just for reporting puposes, define  service name, application name
ENVIRONMENT = 'My Web Environment'

#the log files in the same local machine running this script or in remote hosts  valuese to be either : (True | False )
REMOTE = False

# Apache systems list, hostnames or IPs of apache servers of the enviroment that will SSH accessed to search for access log files
#example HOSTNAMES = ['host1', 'host2', 'host3']
HOSTNAMES = ['localhost']

#System username for remote hosts
USERNAME='aelshafei'

# Logs directory, where the log files  exist in Apache server(s)
DIRECTORY = '/home/aelshafei/log_test'

# Log files common String, the naming constant in log files used for searching
COMMON_LOGFILE_NAME = 'ssl_access_log'

#LogFormat - the LogFormat value defined in Apache Configuration
# for example if it is set as following :
# LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined
# then the value should be :
# LOGFORMAT = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D'
LOGFORMAT = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D'

# Tempraroy directory, where the log files will be copied into and extracted temporary for manipulation before deleting them
TEMP_DIR = '/home/aelshafei/a2lr_tmp'

# Path to Ip Geolocation Database (csv format), can be downloaded from https://lite.ip2location.com/database/ip-country
IP_COUNTRY_DB = 'DATA/IP2LOCATION-LITE-DB1.CSV'

# Default period of Reporting in hours (h) or minutes (m) or days(d), Format: 1d or 2h or 30m 
PERIOD= '200d'

#Is it needed to send an email when running the script
SEND_EMAIL = True

#list of emails to receive an email report .. example : TO_EMAILS = ['elshafei.ah@gmail.com', 'a@b.c', 'd@e.f']

TO_EMAILS = ['elshafei.ah@gmail.com']
