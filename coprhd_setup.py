import pexpect
import time
import sys
import os
import re

def init():
    password = os.getenv('VIPR_PASSWORD')
    if password is None:
        print "VIPR_PASSWORD Env Variable is not Set"
        return (-1)
    else:
        return (0)

def login():
    # First Logout
    print pexpect.run('/opt/storageos/cli/bin/viprcli logout')
    
    # Login to ViprCLI
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authenticate -u root -d /tmp')
    child.logfile = sys.stdout
    password = os.getenv('VIPR_PASSWORD')
    child.expect('Password.*: ')
    child.sendline(password)
    child.expect(pexpect.EOF)
    print child.before
    child.close()

def set_provider():
    # Check out Storage Providers
    result = pexpect.run('/opt/storageos/cli/bin/viprcli storageprovider list')
    test = re.search(r'NAME\s+INTERFACE', result)
    if test is not None:
        print "We have Storage Providers, bailing out!"
        print "Providers: %s" % result
        return(-1)
    else:
        child = pexpect.spawn('/opt/storageos/cli/bin/viprcli storageprovider create -n ScaleIO -provip 10.0.0.37 -provport 22 -u vagrant -secondary_username admin -if scaleio')
        child.logfile = sys.stdout
        child.expect('Enter password of the storage provider:')
        child.sendline('vagrant')
        child.expect('Retype password:')
        child.sendline('vagrant')
        child.expect('Enter password of the secondary password:')
        child.sendline('Scaleio123')
        child.expect('Retype password:')
        child.sendline('Scaleio123')
        child.expect(pexpect.EOF)
        child.before
        child.close()

def create_va(network):
    print pexpect.run('/opt/storageos/cli/bin/viprcli varray create -n ScaleIO_VA')
    command = '/opt/storageos/cli/bin/viprcli network update -varray_add ScaleIO_VA -n ' + network
    print pexpect.run(command)

def get_network():
    # Retry if network isn't created yet
    for i in range (1,20):
        print "Retry is: %s" % i
        results = pexpect.run('/opt/storageos/cli/bin/viprcli  network list')
        result = results.split()
        for entry in result:
            test = re.search(r'\w+-ScaleIONetwork', entry)
            if test is not None:
                print "FOUND IT: %s" % test.group(0)
                return test.group(0)
        time.sleep(1)
    return None

def create_vp():
    print "Creating Virtual Pool"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli vpool create -systemtype scaleio -type block -n VP1 -protocol ScaleIO -va ScaleIO_VA -pt Thick -desc VP1')
    print "Results are: %s" % results

def create_tenant():
    print "Creating Admin Tenant for OS integration"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli tenant create -n admin -domain lab')
    print "Results are: %s" % results

def create_project():
    print "Creating Project for Admin Tenant"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli project create -n admin -tn admin')
    print "Results are: %s" % results

def create_vol():
    print "Creating Volume"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli volume create -tenant admin -pr admin -name TestVol1 -size 1G -vpool VP1 -va ScaleIO_VA')
    print "Results are: %s" % results

def add_keystone_auth():
    password = 'nomoresecrete'
    print "Adding Keystone Authorization"
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authentication add-provider -configfile /home/vagrant/auth_config.cfg')
    child.logfile = sys.stdout
    child.expect('Enter password of the Key1:')
    child.sendline(password)
    child.expect('Retype password:')
    child.sendline(password)
    child.expect(pexpect.EOF)
    child.before
    child.close()

if __name__ == "__main__":
    init()
    login()
    set_provider()    
    network = get_network()
    if network is None:
        print "Error - No Network - Abort!"
        sys.exit(-1)
    create_va(network)
    create_vp()
    create_tenant()
    create_project()
    create_vol()
    add_keystone_auth()

