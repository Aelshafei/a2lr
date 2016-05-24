# a2lr | Apache Access Log Reporter
a2lr project aims to be a comprehensive solution to analyze and generate reports based on **Apache Access Log files** in order to get  overall   accessability status of an online application. It can be run as a cronjob, also, it can be run manually .
This project targets all grades of web application from a tiny web server to a complex enviroment with several web servers .

## Features
- Processing log files from several web servers of the same web environment using SSH or just one local server
- Send reports by Emails
- Eligible to fetch access logs based on custom LogFormat pattrerns
- No need to install custom Python modules
- Support legacy Python versions (Python 2.4)
- Easy Configuration

## How It Works
1- first, it loads the configuration from ```conf.by``` to define the following :
- The period needed to get report about (1 day, 2h ..etc )
- From where the log files will be got (Remotely or locally)

2-  get the files from its location to a temp folder

3- loading the log lines and fetching Data based on the LogFormat configuration

4- calculationg and generating report data

5- format output and send it via email as well as printing to the CLI  

6- delete log files from the temp directory

    

##  Data exported by the script 
- Most Requesting IPs
- Longest URLs response time
- Largest URLs response size
- No of HEAD, GET, POST ... etc requests
- Most Refering URLs
- Most reuqested URLs
- Top requesting countries based on IPs
- Top Browsers
- Top Operating Systems

## How to use

1. set project configuration in ```config.py``` file
```
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
PERIOD= '1d'

#Is it needed to send an email when running the script
SEND_EMAIL = True

#list of emails to receive an email report .. example : TO_EMAILS = ['elshafei.ah@gmail.com', 'a@b.c', 'd@e.f']

TO_EMAILS = ['elshafei.ah@gmail.com']


```

2- Downlaod  Ip Geolocation Database (csv format), can be downloaded from https://lite.ip2location.com/database/ip-country and refer to its path in ```conf.py``` - ```IP_COUNTRY_DB```

3- in case of ```REMOTE``` mode, make sure that remote servers can be automatically SSH connected using keys without prompting password

4- in case of sending report to emails, configure a local SMTP server, add the receptions to ```TO_EMAILS``` in ```conf.py``` file

5- run ```a2lr.py``` and enjoy :-)
