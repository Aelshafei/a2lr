# a2lr | Apache Access Log Reporter - Beta
a2lr is an ongoing project, its aim is to be a comprehensive solution to analyze and generate reports based on **Apache Access Log files** in order to get an overall staus of the  accessability of an online application. It can be run as a cronjob, also, it can be run manually .
This project targets all grades of web application from a tiny web server to a complex enviroment with several web server .

## Features
- can process log files from many web servers of the same web environment using SSH or locally
- Can send reports by Emails
- Eligible to custome LogFormat pattrerns
- No need to install custom Python modules
- Support legacy Python versions (Python 2.4)
- Easy Configuration

## How It Works
1- Script loads the configuration to define the following :
- The period needed to get report about (1 day, 2h ..etc )
- From where the log files will be got (Remotely or locally)

2-  get the files from its location to a temp folder

3- loading the log lines and fetching Data based on the LogFormat configuration

4- calculationg and generating report data

5- format output and send it via email as well as printing to the CLI  

    

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

1. set project configuration in config.py file
```
## in this section some basic definition is set as follows :

#ENVIRONMENT, just for reporting puposes, you may define domain, service name, application name
ENVIROMENT = 'My Web Environment'

#the log files in the same local machine running this script or in remote hosts  valuese to be either : (True | False )
REMOTE = False

# Apache systems list, hostnames or IPs of apache servers of the enviroment that will SSH accessed to search for access log files
HOSTNAMES = ['localhost']

#System username for remote hosts
USERNAME='aelshafei'

# Logs directory, where the log files  exist in Apache servers
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

# Default period of Reporting in hours (h) or minutes (m) or days(d), Format: 1d or 2h or 30m 
PERIOD= '100d'

#list of emails to receive an email report
TO_EMAILS = ['elshafei.ah@gmail.com']

```

2- in case of ```REMOTE``` mode, make sure that remote servers can be automatically SSH connected using keys without prompting password


3- run ```a2lr.py``` and enjoy :-)
