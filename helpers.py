import conf

#Command line escape sequences for output formating
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#Log Format tokens dictionary
TOKEN_DICT = {
                  '%h':  'remote_host',
                  '%l':  'remote_logname',
                  '%u':  'remote_user',
                  '%t':  'time_stamp',
                  '%r':  'request_line',
                  '%>s': 'status',
                  '%b':  'response_size',
                  '%{Referer}i':    'referer_url',
                  '%{User-Agent}i': 'user_agent',
                  '%D': 'response_time'
                }

#function to generate the period placeholder for log files searching command
def calculate_period():
	#based on PERIOD constant definition, local and remote command placeholders to be calculated

	#removing any whitespaces and fetching PERIOD args
	period_args = ''.join(conf.PERIOD.split())
	period_measure = period_args[-1].lower()
	period_val = period_args[0:-1]

	#print period_measure
	#check if period measure unit is valid
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


	if period_measure == 'm':
		if conf.REMOTE:
			period_placeholder = '-mmin -' + str(period_val)
		else:
			period_placeholder = 60 * period_val
	elif period_measure == 'h': 
		if conf.REMOTE:
			period_placeholder = '-mmin -' + str(period_val * 60)
		else:
			period_placeholder = 60 * 60 * period_val
	else: 
		#days
		if conf.REMOTE:
			period_placeholder = '-mtime -' + str(period_val)
		else:
			period_placeholder = 60 * 60 * 24 * period_val

	

	#print period_placeholder
	return period_placeholder


#Analytics Data variables Definions

HTTP_METHODS_COUNT = {
	'GET' : 0,
	'POST' : 0,
	'OPTIONS' : 0,
	'CONNECT' : 0,
	'DELETE' : 0,
	'PUT' : 0,
	'HEAD': 0
}

MOST_REQUESTING_IPs = {}

LONGEST_URL_RESPONSE_TIME = {}

LARGEST_URL_RESPONSE_SIZE = {}

MOST_REFERING_URLS = {}

MOST_REQUESTING_USER_AGENTS = {}

MOST_REQUESTING_URLS = {}

MOST_REQUESTING_CLIENTS = {}

MOST_REQUESTING_OS = {}

TOP_REQUESTING_COUNTERIES = {}

HTTP_STATUS_CODE_OCCUR = {
	'100' : 0,
	'101' : 0,
	'102' : 0,
	'200' : 0,
	'201' : 0,
	'202' : 0,
	'203' : 0,
	'204' : 0,
	'205' : 0,
	'206' : 0,
	'207' : 0,
	'208' : 0,
	'226' : 0,
	'300' : 0,
	'301' : 0,
	'302' : 0,
	'304' : 0,
	'305' : 0,
	'306' : 0,
	'307' : 0,
	'308' : 0,
	'400' : 0,
	'401' : 0,
	'402' : 0,
	'403' : 0,
	'404' : 0,
	'405' : 0,
	'406' : 0,
	'407' : 0,
	'408' : 0,
	'409' : 0,
	'410' : 0,
	'411' : 0,
	'412' : 0,
	'413' : 0,
	'414' : 0,
	'415' : 0,
	'416' : 0,
	'417' : 0,
	'418' : 0,
	'421' : 0,
	'422' : 0,
	'423' : 0,
	'424' : 0,
	'426' : 0,
	'428' : 0,
	'429' : 0,
	'431' : 0,
	'451' : 0,
	'501' : 0,
	'502' : 0,
	'503' : 0,
	'504' : 0,
	'505' : 0,
	'506' : 0,
	'507' : 0,
	'508' : 0,
	'510' : 0,
	'511' :0
}