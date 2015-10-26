import pexpect
import json
import time
import sys
import os
import re
import config

def init():
    coprhd_password = config.coprhd_password
    coprhd_host = config.coprhd_host
    os_password = config.os_password
    auth_url = config.os_auth_url
    os_user = config.os_username
    os_tenant = config.os_tenant_name
    
    if password is None or auth_url is None or os_user is None or os_tenant is None or coprhd_password is None or coprhd_host is None:
        print "Need to set OS Credentials: OS_PASSWORD, OS_AUTH_URL, OS_USERNAME, OS_TENANT_NAME"
        print "and the COPRHD Credentials: COPRHD_HOST, COPRHD_PASSWORD"
        print "Add them to the config.py file"
        sys.exit(-1)
    else:
        return (0)

def get_projects(name):
    command0 = 'openstack project show ' + name + ' -f json'
    results = pexpect.run(command0)
    json_dump = json.loads(results)
    for field in json_dump:
        if field['Field'] == 'id':
            id = field['Value']
            print "Id is: %s" % id
            return id
    raise (Exception("No ID for Admin Project"))

def get_service(name):
    print "Getting Service for volumev2"
    command0 = 'openstack service show ' + name + ' -f json'
    results = pexpect.run(command0)
    json_dump = json.loads(results)
    for field in json_dump:
        if field['Field'] == 'id':
            id = field['Value']
            print "Id is: %s" % id
            return id
    raise (Exception("No ID for %s" % name)) 

def get_endpoint(name):
    command0 = 'openstack endpoint show ' + name + ' -f json'
    results = pexpect.run(command0)
    json_dump = json.loads(results)
    for field in json_dump:
        if field['Field'] == 'id':
            id = field['Value']
            print "Id is: %s" % id
            return id
    raise (Exception("No ID for %s" % name)) 

def create_endpoint_for_ch(service_id):
    print "Creating Endpoint for CH in Openstack"
    command0 = 'openstack endpoint create ' + service_id + ' --publicurl=http://10.0.0.11:8080/v2/$\(tenant_id\)s --adminurl=http://10.0.0.11:8080/v2/$\(tenant_id\)s --internalurl=http://10.0.0.11:8080/v2/$\(tenant_id\)s --region=RegionOne'
    results = pexpect.run(command0)
    print "Results from executing endpoint create for CH: %s" % results

def delete_endpoint(id):
    command0 = 'openstack endpoint delete ' + id
    results = pexpect.run(command0)
    print "Results of endpoint delete: %s" % results

def add_tenant_id(pid):
    command0 = '/opt/storageos/cli/bin/viprcli -hostname '+ config.coprhd_host + ' tenant create -n admin -domain lab -key tenant_id -value ' + pid
    results = pexpect.run(command0)
    print "Results from add_tenant: %s" % results

def create_project():
    print "Creating Project for Admin Tenant"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli project create -n admin -tn admin -hostname ' + config.coprhd_host)
    print "Results are: %s" % results

def tag_project(project_id):
    print "Tagging Admin Project "
    command0 = '/opt/storageos/cli/bin/viprcli project tag -hostname ' + config.coprhd_host + ' -n admin -tn admin -add ' + project_id
    results = pexpect.run(command0)
    print "Results are: %s" % results

def login():
    # First Logout
    print pexpect.run('/opt/storageos/cli/bin/viprcli logout -hostname '+ config.coprhd_host)
    
    # Login to ViprCLI
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authenticate -u root -d /tmp -hostname ' + config.coprhd_host)
    child.logfile = sys.stdout
    password = config.coprhd_password
    print child.before
    child.expect('Password.*: ')
    child.sendline(password)
    child.expect(pexpect.EOF)
    print child.before
    child.close()

def create_va(network):
    print pexpect.run('/opt/storageos/cli/bin/viprcli varray create -n ScaleIO_VA -hostname '+ config.coprhd_host)
    command = '/opt/storageos/cli/bin/viprcli network update -varray_add ScaleIO_VA -n ' + network + ' -hostname ' + config.coprhd_host
    print pexpect.run(command)

def get_network():
    # Retry if network isn't created yet
    for i in range (1,20):
        print "Retry is: %s" % i
        results = pexpect.run('/opt/storageos/cli/bin/viprcli  network list -hostname ' + config.coprhd_host)
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
    results = pexpect.run('/opt/storageos/cli/bin/viprcli vpool create -systemtype scaleio -type block -n VP1 -protocol ScaleIO -va ScaleIO_VA -pt Thick -desc VP1 -hostname '+ config.coprhd_host)
    print "Results are: %s" % results

def create_vol():
    print "Creating Volume"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli volume create -pr admin -name TestVol1 -size 1G -vpool VP1 -va ScaleIO_VA -hostname ' + config.coprhd_host)
    print "Results are: %s" % results

def add_keystone_auth():
    password = config.os_password
    print "Adding Keystone Authorization"
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authentication add-provider -configfile /home/vagrant/auth_config.cfg -hostname ' + config.coprhd_host)
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
    print "Coprhd_host is: %s" % config.coprhd_host
    print "Coprhd_host is: %s" % config.coprhd_host
    login()
    # Add Keystone as Auth Provider
    add_keystone_auth()
    # Get OS Project id for admin project
    os_project_id = get_projects('admin')
    # Add the ID for admin project into CH
    add_tenant_id(os_project_id)
    # Add CH Project with admin tenant
    create_project()
    tag_project(os_project_id)

    # Remap Volume service to CH
    service_id = get_service('volumev2')
    endpoint_id = get_endpoint('volumev2')
    delete_endpoint(endpoint_id)
    create_endpoint_for_ch(service_id)
