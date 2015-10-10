import pexpect
import json
import sys
import os
import re
import logging

# Hack for limiting urllib3 warnins about unverified HTTPS requests
env={'PYTHONWARNINGS':"ignore"}

def init():
    password = os.getenv('VIPR_PASSWORD')
    if password is None:
        print "VIPR_PASSWORD Env Variable is not Set"
        sys.exit(-1)
    logging.captureWarnings(True)

def login():
    # First Logout
    print pexpect.run('/opt/storageos/cli/bin/viprcli logout',env=env)
    
    # Login to ViprCLI
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authenticate -u root -d /tmp',env=env)
    child.logfile = sys.stdout
    password = os.getenv('VIPR_PASSWORD')
    child.expect('Password.*: ')
    child.sendline(password)
    child.expect(pexpect.EOF)
    print child.before
    child.close()

def set_provider():
    # Check out Storage Providers
    result = pexpect.run('/opt/storageos/cli/bin/viprcli storageprovider list',env=env)
    test = re.search(r'NAME\s+INTERFACE', result)
    if test is not None:
        print "We have Storage Providers, bailing out!"
        print "Providers: %s" % result
        return(-1)
    else:
        child = pexpect.spawn('/opt/storageos/cli/bin/viprcli storageprovider create -n ScaleIO -provip 10.0.0.37 -provport 22 -u vagrant -secondary_username admin -if scaleio',env=env)
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
    print pexpect.run('/opt/storageos/cli/bin/viprcli varray create -n ScaleIO_VA',env=env)
    command = '/opt/storageos/cli/bin/viprcli network update -varray_add ScaleIO_VA -n ' + network
    print pexpect.run(command,env=env)

def get_network():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli  network list',env=env)
    result = results.split()
    for entry in result:
        test = re.search(r'\w+-ScaleIONetwork', entry)
        if test is not None:
            print "FOUND IT: %s" % test.group(0)
            return test.group(0)
    
    return None

def get_storage_system():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli storagesystem list',env=env)
    result = results.split()
    print "Result is: %s" % result
    for entry in result:
        test = re.search(r'SCALEIO\+\w+\+pdomain', entry)
        if test is not None:
            print "FOUND IT: %s" % test.group(0)
            return test.group(0)
    return None

def create_vp():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli vpool create -systemtype scaleio -type block -n VP1 -protocol ScaleIO -va ScaleIO_VA -pt Thick -desc VP1',env=env)

def create_vol():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli volume create -pr admin -name TestVol1 -size 1G -vpool VP1 -va ScaleIO_VA',env=env)

def remove_system(system):
    command0 = '/opt/storageos/cli/bin/viprcli storagesystem deregister -n ' + system + ' -t scaleio'
    results = pexpect.run(command0,env=env)
    print "Results of De-registering System: %s" % results

    command1 = '/opt/storageos/cli/bin/viprcli storagesystem delete -n ' + system + ' -t scaleio'
    results = pexpect.run(command1,env=env)
    print "Results of Deleting System: %s" % results

    command2 = '/opt/storageos/cli/bin/viprcli storageprovider delete -n ScaleIO'
    results = pexpect.run(command2,env=env)
    print "Results of Deleting Provider: %s" % results

def get_endpoints(network):
    # Remove the varray from the network first
    print "Getting Endpoints"
    command0 = '/opt/storageos/cli/bin/viprcli network show -n ' + network 
    results = pexpect.run(command0,env=env)
    json_dump = json.loads(results)
    # Pull Endpoints
    print "Endpoints are: %s" % json_dump['endpoints']
    return(json_dump['endpoints'])
    

def remove_network(network,endpoints):
    # Remove the varray from the network first
    command0 = '/opt/storageos/cli/bin/viprcli network update -varray_remove ScaleIO_VA -n ' + network
    results = pexpect.run(command0,env=env)
    print "Results on removing varray : %s" % results

    # De-register Network
    command1 = '/opt/storageos/cli/bin/viprcli network deregister -n ' + network
    results = pexpect.run(command1,env=env)
    print "Results on deregistering network : %s" % results

    # Need to remove the endpoints before removing the network
    for endpoint in endpoints:
        command2 = '/opt/storageos/cli/bin/viprcli network endpoint remove -n ' + network + ' -e ' + endpoint
        results = pexpect.run(command2,env=env)
        print "Results on removing endpoint: %s" % results

    command3 = '/opt/storageos/cli/bin/viprcli network delete -n ' + network
    results = pexpect.run(command3,env=env)
    print "Results on removing network: %s" % results

def remove_vols():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli volume delete -n TestVol1 -tenant admin -pr admin',env=env)

def remove_vpool():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli vpool delete -n VP1 -type block',env=env)

def remove_va():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli varray delete -n ScaleIO_VA',env=env)

def remove_project():
    command0 = '/opt/storageos/cli/bin/viprcli project delete -n admin -tn admin'
    results = pexpect.run(command0,env=env)
    print "Results of Deleting Project: %s" % results

def remove_tenant():
    command0 = '/opt/storageos/cli/bin/viprcli tenant delete -n admin'
    results = pexpect.run(command0,env=env)
    print "Results of Deleting Project: %s" % results

def remove_hosts():
    command0 = '/opt/storageos/cli/bin/viprcli host delete -n 10.0.0.36 -t Other'
    command1 = '/opt/storageos/cli/bin/viprcli host delete -n 10.0.0.37 -t Other'
    command2 = '/opt/storageos/cli/bin/viprcli host delete -n 10.0.0.38 -t Other'
    results = pexpect.run(command0,env=env)
    results = pexpect.run(command1,env=env)
    results = pexpect.run(command2,env=env)

def remove_key_auth():
    command0 = '/opt/storageos/cli/bin/viprcli authentication delete-provider -n Key1'
    results = pexpect.run(command0,env=env)
    print "Results are: %s" % results

if __name__ == "__main__":
    init()
    login()
    network = get_network()
    if network is None:
        print "No Network to Delete"
    else:
        endpoints = get_endpoints(network)
        remove_network(network,endpoints)
    remove_vols()
    remove_vpool()
    remove_va()
    remove_hosts()
    remove_project()
    remove_tenant()
    remove_key_auth()
    system = get_storage_system()
    if system is None:
        print "Error - No Storage System - Abort!"
        sys.exit(-1)
    remove_system(system)


