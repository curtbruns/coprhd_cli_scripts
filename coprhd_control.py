#!/usr/bin/python

import pexpect
import time
import sys
import os
import re
import config
import argparse
import json

# Hack for limiting urllib3 warnins about unverified HTTPS requests
env={'PYTHONWARNINGS':"ignore",'VIPR_HOSTNAME':config.coprhd_host}

def init():
    if (config.root_password is None or config.scaleio_mdm1_ip is None 
        or config.os_password is None or config.os_auth_url is None or 
        config.os_username is None or config.os_tenant_name is None or 
        config.coprhd_password is None or config.coprhd_host is None):
        print ("Need to set OS Credentials: OS_PASSWORD, OS_AUTH_URL,\
                OS_USERNAME, OS_TENANT_NAME")
        print ("and the COPRHD Credentials: COPRHD_HOST, COPRHD_PASSWORD")
        print ("Add them to the config.py file or you forgot to \
                'source coprhd_settings'")
        sys.exit(-1)

    # Get the Command-Line Settings to direct us
    parser = argparse.ArgumentParser(description='Setup, Check, or Teardown \
                                    CoprHD Config with ScaleIO and Devstack.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-c', '--check', help="Check if VArray, VPool, Networks,\
                        etc are setup", action="store_true")
    group.add_argument('-s', '--setup', help="Setup CoprHD based on config.py \
                        settings with VArray, Vpool, etc", action="store_true")
    group.add_argument('-d', '--delete', help="Tear Down CoprHD, removing \
                        Storage System, VA, VP, Network, Endpoints, etc", 
                        action="store_true")
    args = parser.parse_args()
    return args

def login():
    # First Logout
    print pexpect.run('/opt/storageos/cli/bin/viprcli logout',env=env)
    
    # Login to ViprCLI
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authenticate -u root \
                            -d /tmp',env=env)
    child.logfile = sys.stdout
    password = config.coprhd_password
    child.expect('Password.*: ')
    child.sendline(password)
    child.expect(pexpect.EOF)
    #print child.before
    child.close()

def set_provider():
    # Check out Storage Providers
    result = pexpect.run('/opt/storageos/cli/bin/viprcli storageprovider list'
                        ,env=env)
    test = re.search(r'NAME\s+INTERFACE', result)
    password = config.scaleio_password
    if test is not None:
        print "We have Storage Providers, bailing out!"
        print "Providers: %s" % result
        return(-1)
    else:
        child = pexpect.spawn('/opt/storageos/cli/bin/viprcli storageprovider \
                            create -n ScaleIO -provip '+config.scaleio_mdm1_ip+\
                            ' -provport 443 -u admin -ssl -if scaleioapi',
                            env=env)
        child.logfile = sys.stdout
        child.expect('Enter password of the storage provider:')
        child.sendline(password)
        child.expect('Retype password:')
        child.sendline(password)
        child.expect(pexpect.EOF)
        child.before
        child.close()

def create_va(network):
    print "====> Creating Virtual Array, ScaleIO_VA"
    print pexpect.run('/opt/storageos/cli/bin/viprcli varray create -n \
                        ScaleIO_VA',env=env)
    command = '/opt/storageos/cli/bin/viprcli network update -varray_add \
                ScaleIO_VA -n ' + network
    print pexpect.run(command,env=env)

def get_network(retry=20):
    print "====> Searching Network"
    # Retry if network isn't created yet
    for i in range (1,retry):
        results = pexpect.run('/opt/storageos/cli/bin/viprcli  network list'
                                ,env=env)
        result = results.split()
        for entry in result:
            test = re.search(r'\w+-ScaleIONetwork', entry)
            if test is not None:
                print "FOUND IT: %s" % test.group(0)
                return test.group(0)
        time.sleep(1)
        print "Retry is: %s" % i
    return None

def create_vp():
    print "====> Creating Virtual Pool"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli vpool create \
                            -systemtype scaleio -type block -n VP1 \
                            -protocol ScaleIO -va ScaleIO_VA -pt Thick \
                            -desc VP1',env=env)
    if len(results) > 0:
        print "Results are: %s" % results

def create_tenant():
    print "====> Creating Admin Tenant"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli tenant create -n \
                            admin -domain lab',env=env)
    if len(results) > 0:
        print "Results are: %s" % results

def create_vol():
    print "====> Creating Volume"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli volume create \
                            -tenant admin -pr admin -name TestVol1 -size 1G \
                             -vpool VP1 -va ScaleIO_VA',env=env)
    if len(results) > 0:
        print "Results are: %s" % results

def add_keystone_auth():
    password = config.os_password
    print "====> Adding Keystone Auth"
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authentication \
                            add-provider -configfile \
                            /home/vagrant/auth_config.cfg',env=env)
    child.logfile = sys.stdout
    child.expect('Enter password of the Key1:')
    child.sendline(password)
    child.expect('Retype password:')
    child.sendline(password)
    child.expect(pexpect.EOF)
    child.before
    child.close()

def get_storage_system():
    results = pexpect.run('/opt/storageos/cli/bin/viprcli storagesystem list'
                        ,env=env)
    result = results.split()
    #print "Result is: %s" % result
    for entry in result:
        test = re.search(r'SCALEIO\+\w+\+pdomain', entry)
        if test is not None:
            #print "FOUND IT: %s" % test.group(0)
            return test.group(0)
    return None

def remove_system(system):
    print "====> Removing Storage System"
    command0 = '/opt/storageos/cli/bin/viprcli storagesystem deregister -n ' \
                + system + ' -t scaleio'
    results = pexpect.run(command0,env=env)
    if len(results) > 0:
        print "Results of De-registering System: %s" % results

    command1 = '/opt/storageos/cli/bin/viprcli storagesystem delete -n ' \
                + system + ' -t scaleio'
    results = pexpect.run(command1,env=env)
    if len(results) > 0:
        print "Results of Deleting System: %s" % results

    command2 = '/opt/storageos/cli/bin/viprcli storageprovider delete -n \
                ScaleIO'
    results = pexpect.run(command2,env=env)
    if len(results) > 0:
        print "Results of Deleting Provider: %s" % results

def get_endpoints(network):
    # Remove the varray from the network first
    print "====> Getting Endpoints"
    command0 = '/opt/storageos/cli/bin/viprcli network show -n ' + network 
    results = pexpect.run(command0,env=env)
    json_dump = json.loads(results)
    # Pull Endpoints
    print "Endpoints are: %s" % json_dump['endpoints']
    return(json_dump['endpoints'])
    

def remove_network(network,endpoints):
    # Remove the varray from the network first
    print "====> Removing Varray"
    command0 = '/opt/storageos/cli/bin/viprcli network update -varray_remove \
                ScaleIO_VA -n ' + network
    results = pexpect.run(command0,env=env)
    if len(results) > 0:
        print "Results on removing varray : %s" % results

    # De-register Network
    print "====> De-register Network"
    command1 = '/opt/storageos/cli/bin/viprcli network deregister -n ' + network
    results = pexpect.run(command1,env=env)
    if len(results) > 0:
        print "Results on deregistering network : %s" % results

    # Need to remove the endpoints before removing the network
    print "====> Remove Network Endpoints"
    for endpoint in endpoints:
        command2 = '/opt/storageos/cli/bin/viprcli network endpoint remove -n '\
                     + network + ' -e ' + endpoint
        results = pexpect.run(command2,env=env)
        if len(results) > 0:
            print "Results on removing endpoint: %s" % results

    print "====> Deleting Network"
    command3 = '/opt/storageos/cli/bin/viprcli network delete -n ' + network
    results = pexpect.run(command3,env=env)
    if len(results) > 0:
        print "Results on removing network: %s" % results

def remove_vols():
    print "====> Deleting TestVol1"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli volume delete -n \
                            TestVol1 -tenant admin -pr admin',env=env)

def remove_vpool():
    print "====> Deleting Virtual Pool, VP1"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli vpool delete -n VP1\
                             -type block',env=env)
    if len(results) > 0:
        print "Results of removing Virtual Pool: %s" % results

def remove_va():
    print "====> Deleting Virtual Array, ScaleIO_VA"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli varray delete -n \
                            ScaleIO_VA',env=env)
    if len(results) > 0:
        print "Results of removing VArray: %s" % results

def remove_project():
    print "====> Deleting Admin Project"
    # Removing the tenant Admin role makes tenant unavailable but it still 
    # survives as the 'id' but it's not available via command line
#    command0 = '/opt/storageos/cli/bin/viprcli tenant delete-role -n admin -role TENANT_ADMIN -subject-id root'
    command1 = '/opt/storageos/cli/bin/viprcli project delete -n admin \
                -tn admin'
#    results = pexpect.run(command0,env=env)
#    print "Results of Deleting Role: %s" % results
    results = pexpect.run(command1,env=env)
    if len(results) > 0:
        print "Results of Deleting Project: %s" % results

def remove_tenant():
    print "====> Deleting Admin Tenant"
    """This currently fails due to tenant having an outstanding task"""
    command0 = '/opt/storageos/cli/bin/viprcli tenant delete -n admin'
    results = pexpect.run(command0,env=env)
    if len(results) > 0:
        print "Results of Deleting Tenant: %s" % results

def remove_hosts():
    print "====> Deleting Hosts"
    command0 = '/opt/storageos/cli/bin/viprcli host delete -n '\
                +config.scaleio_mdm1_ip+' -t Other'
    command1 = '/opt/storageos/cli/bin/viprcli host delete -n '\
                +config.scaleio_mdm2_ip+' -t Other'
    command2 = '/opt/storageos/cli/bin/viprcli host delete -n '\
                +config.scaleio_tb_ip+' -t Other'
    results0 = pexpect.run(command0,env=env)
    results1 = pexpect.run(command1,env=env)
    results2 = pexpect.run(command2,env=env)
    if len(results0) > 0 or len(results1) > 0 or len(results2) > 0:
        print "Results of deleting mdm1: %s, mdm2: %s, tb: %s" % \
            (results0, results1, results2)

def remove_key_auth():
    print "====> Deleting Keystone Auth Provider"
    command0 = '/opt/storageos/cli/bin/viprcli authentication delete-provider \
                 -n Key1'
    results = pexpect.run(command0,env=env)
    if len(results) > 0:
        print "Results are: %s" % results

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
    print "====> Getting Service for volumev2"
    command0 = 'openstack service show ' + name + ' -f json'
    results = pexpect.run(command0)
    json_dump = json.loads(results)
    for field in json_dump:
        if field['Field'] == 'id':
            id = field['Value']
            print "Id is: %s" % id
            return id
    raise (Exception("No ID for %s" % name)) 

def get_os_endpoint(name):
    command0 = 'openstack endpoint show ' + name + ' -f json'
    results = pexpect.run(command0)
    json_dump = json.loads(results)
    for field in json_dump:
        if field['Field'] == 'id':
            id = field['Value']
            print "Id is: %s" % id
            return id
    raise (Exception("No ID for %s" % name)) 

def create_os_endpoint_for_ch(service_id):
    print "====> Creating Endpoint for CoprHD in OpenStack"
    command0 = 'openstack endpoint create ' + service_id + ' --publicurl=http://'+config.coprhd_host+':8080/v2/$\(tenant_id\)s --adminurl=http://'+config.coprhd_host+':8080/v2/$\(tenant_id\)s --internalurl=http://'+config.coprhd_host+':8080/v2/$\(tenant_id\)s --region=RegionOne'
    results = pexpect.run(command0)
    if len(results) > 0:
        print "Results from executing endpoint create for CH: %s" % results

def delete_os_endpoint(id):
    print "====> Deleting OpenStack Endpoint"
    command0 = 'openstack endpoint delete ' + id
    results = pexpect.run(command0)
    if len(results) > 0:
        print "Results of endpoint delete: %s" % results

def add_tenant_id(pid):
    print "====> Adding Tenant"
    command0 = '/opt/storageos/cli/bin/viprcli -hostname '+ config.coprhd_host+' tenant create -n admin -domain lab -key tenant_id -value ' + pid
    results = pexpect.run(command0)
    if len(results) > 0:
        print "Results from add_tenant: %s" % results

def create_project():
    print "====> Creating Admin Project"
    results = pexpect.run('/opt/storageos/cli/bin/viprcli project create -n admin -tn admin -hostname ' + config.coprhd_host)
    if len(results) > 0:
        print "Results are: %s" % results

def tag_project(project_id):
    print "====> Tagging Admin Project"
    command0 = '/opt/storageos/cli/bin/viprcli project tag -hostname ' + config.coprhd_host + ' -n admin -tn admin -add ' + project_id
    results = pexpect.run(command0)
    if len(results) > 0:
        print "Results are: %s" % results

def os_integration():
    """OS Integration adds the OpenStack pieces into CH and 
        adds the CH Endpoint into OS Keystone"""
    add_keystone_auth()
    os_project_id = get_projects('admin')
    add_tenant_id(os_project_id)
    # Add CH Project with admin tenant
    create_project()
    tag_project(os_project_id)
    # Remap Volume service to CH
    service_id = get_service('volumev2')
    endpoint_id = get_os_endpoint('volumev2')
    delete_os_endpoint(endpoint_id)
    create_os_endpoint_for_ch(service_id)

def coprhd_setup():
    os_integration()
    # Setup CoprHD
    set_provider()    
    network = get_network(20)
    if network is None:
        print "Error - No Network - Abort!"
        sys.exit(-1)
    create_va(network)
    create_vp()
    # These are done in OS_Integration Step
    #    create_tenant()
    #    create_project()
    # Don't create vol - tenant can't be deleted if vol is created
    # create_vol()

def coprhd_delete():
    network = get_network(retry=2)
    if network is None:
        print "No Network to Delete"
    else:
        endpoints = get_endpoints(network)
        remove_network(network,endpoints)
    # Debug - see if this is causing issue with tenant delete
    # remove_vols()
    remove_vpool()
    remove_va()
    remove_hosts()
    remove_project()
    # If volumes were created, you cannot remove tenant
    remove_tenant()
    remove_key_auth()
    system = get_storage_system()
    if system is None:
        print "Error - No Storage System - Abort!"
        sys.exit(-1)
    remove_system(system)


def coprhd_check():
    print "====> Storage System(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli storagesystem list')
    print pexpect.run(command0,env=env)

    print "====> Virtual Array(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli varray list')
    print pexpect.run(command0,env=env)

    print "====> Virtual Pool(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli vpool list')
    data = pexpect.run(command0,env=env)
    print data

    if len(data) > 0:
        print "====> Volume(s)"
        command0 = '/opt/storageos/cli/bin/viprcli volume list -pr admin \
                    -tn admin'
        print pexpect.run(command0,env=env)

if __name__ == "__main__":
    args = init()
    login()
    if args.setup:
        coprhd_setup()
    elif args.delete:
        coprhd_delete()
    elif args.check:
        coprhd_check()

