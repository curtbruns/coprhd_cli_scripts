#!/usr/bin/python
import pexpect
import config
import re

# Hack for limiting urllib3 warnins about unverified HTTPS requests
env={'PYTHONWARNINGS':"ignore",'VIPR_HOSTNAME':config.coprhd_host}


# Login to ViprCLI
child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authenticate -u root -d /tmp',env=env)

password = config.coprhd_password
child.expect('Password.*: ')
child.sendline(password)
child.expect(pexpect.EOF)
# Did we login correctly
test = re.search(r'root : Authenticated Successfully', child.before)
child.close()

project_list = ["demoProject", "invisible_to_adminProject", "adminProject", "alt_demoProject", "serviceProject"]
tenant_list = ["OpenStack demo", "OpenStack invisible_to_admin", "OpenStack admin", "OpenStack alt_demo", "OpenStack service"]

for i in range(1, len(project_list)):
	print "Deleting Project: {} and Tenant: {}".format(project_list[i], tenant_list[i])
	command = '/opt/storageos/cli/bin/viprcli project delete -tn "' + tenant_list[i] + '" -n ' + project_list[i]
	print "Sending command: %s" % command
	results = pexpect.run(command)
	print "Results from project delete: %s " % results
	command = '/opt/storageos/cli/bin/viprcli tenant delete -n "' + tenant_list[i] + '"'
	print "Sending command: %s" % command
	results = pexpect.run(command)
	print "Results from tenant delete: %s " % results
