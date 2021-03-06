#!/usr/bin/python
import pexpect
import time
import sys
import os
import re
import config
import argparse
import json
import getpass
import shlex
import socket
import subprocess

# Hack for limiting urllib3 warnins about unverified HTTPS requests
env={'PYTHONWARNINGS':"ignore",'VIPR_HOSTNAME':config.coprhd_host}
err_file = open("_tmp.err", "w")

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
                        are setup", action="store_true")
    group.add_argument('-s', '--setup', help="Setup CoprHD with ScaleIO and setup \
                        VArray and Vpools", action="store_true")
    group.add_argument('-o', '--openstack', help="Setup CoprHD with DevStack \
                        and ScaleIO with VArray, Vpool, and Keystone Auth", action="store_true")
    group.add_argument('-d', '--delete', help="Tear Down CoprHD, removing \
                        Storage System, VArray, VPools, Networks, and Endpoints", 
                        action="store_true")
    parser.add_argument('-v', '--verbose', help="Enable Debug Output", action="store_true")
    args = parser.parse_args()
    return args

def login():
    print "====> Logging into CoprHD"
    # Check User is storageos
    if getpass.getuser() != 'storageos':
        print "You need to be storageos to run this correctly!"
        sys.exit(-1)
    
    # First Logout
    cmd = '/opt/storageos/cli/bin/viprcli logout'
    run_cmd(cmd)
    
    # Login to ViprCLI
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authenticate -u root \
                            -d /tmp',env=env)
	
    if args.verbose:
	child.logfile = sys.stdout
    password = config.coprhd_password
    child.expect('Password.*: ')
    child.sendline(password)
    child.expect(pexpect.EOF)
    # Did we login correctly
    test = re.search(r'root : Authenticated Successfully', child.before)
    child.close()
    if test is None:
	print "CoprHD Login is Incorrect. Check coprhd_settings file"
	sys.exit(-1)

def set_provider():
    print "====> Adding Storage Provider"
    # Check out Storage Providers
    cmd = '/opt/storageos/cli/bin/viprcli storageprovider list'
    result = run_cmd(cmd)
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
	if args.verbose:
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
    cmd = '/opt/storageos/cli/bin/viprcli varray create -n  ScaleIO_VA'
    run_cmd(cmd)
    cmd = '/opt/storageos/cli/bin/viprcli network update -varray_add \
                ScaleIO_VA -n ' + network
    print(run_cmd(cmd))

def get_networks(retry=20):
    network_list = []
    print "====> Searching Network"
    # Retry if network isn't created yet
    for i in range (1,retry):
        cmd = '/opt/storageos/cli/bin/viprcli network list'
        results = run_cmd(cmd)
        if len(results) > 0:
            result = results.split('\n')
            # Skip header row and grab Networks
            for i in range (1, len(result)-1):
                entry = (result[i].split())[0]
                print "====> Found Network: %s" % entry
                network_list.append(entry)
            return network_list
        else:
            time.sleep(1)
            if i > 1:
                print "Retry is: %s" % i
    return None

def create_vp():
    print "====> Creating Virtual Pool: ThickSATA"
    cmd = '/opt/storageos/cli/bin/viprcli vpool create -systemtype scaleio -type block -n ThickSATA -protocol ScaleIO -va ScaleIO_VA -pt Thick -desc VP1 -drivetype SATA'
    results = run_cmd(cmd)
    if len(results) > 0:
        print "Results are: %s" % results
        sys.exit(-1)

# If we have an "admin" tenant, then we're doing DevStack integration
def get_tenant():
    print "====> Get Tenant"
    cmd = '/opt/storageos/cli/bin/viprcli tenant list'
    results = run_cmd(cmd)
    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grab Tenants
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            if entry == "admin":
                print "We have admin tenant - we are doing OS integration"
                return "admin"
        # If no admin tenant, we use default Provider Tenant
        return 'Provider Tenant'
    else:
        return None

def create_tenant():
    print "====> Creating Admin Tenant"
    cmd = '/opt/storageos/cli/bin/viprcli tenant create -n  admin -domain lab'
    results = run_cmd(cmd)
    if len(results) > 0:
        print "Results are: %s" % results

def create_vol():
    print "====> Creating Volume"
    cmd = '/opt/storageos/cli/bin/viprcli volume create  -tenant admin -pr admin -name TestVol1 -size 1G -vpool VP1 -va ScaleIO_VA'
    results = run_cmd(cmd)
    if len(results) > 0:
        print "Results are: %s" % results

def add_keystone_auth():
    password = config.os_password
    print "====> Adding Keystone Auth"
    child = pexpect.spawn('/opt/storageos/cli/bin/viprcli authentication \
                            add-provider -configfile \
                            ./auth_config.cfg',env=env)
    if args.verbose:
        child.logfile = sys.stdout
    child.expect('Enter password of the Key1:')
    child.sendline(password)
    child.expect('Retype password:')
    child.sendline(password)
    child.expect(pexpect.EOF)
    child.before
    child.close()

def get_storage_systems():
    system_list = []
    print "====> Get Storage Systems"
    cmd = '/opt/storageos/cli/bin/viprcli storagesystem list'
    results = run_cmd(cmd)
    result = results.split()
    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grab System and Type
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            print "Entry is: %s" % entry
            sys_dict = dict()
            try:
                sys_type = (result[i].split())[2]
                sys_dict[entry] = sys_type
            except IndexError:
                # Don't have System Type if Network wasn't installed
                sys_type = "blank"
                sys_dict[entry] = sys_type
            print "====> Found System %s and Type: %s" % (entry, sys_type)
            system_list.append(sys_dict)
            #print "System list is: %s" % system_list
        return system_list
    else:
        return None

def get_storage_providers():
    system_list = []
    print "====> Get Storage Providers"
    cmd = '/opt/storageos/cli/bin/viprcli storageprovider list'
    results = run_cmd(cmd)
    result = results.split()
    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grab Provider
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            system_list.append(entry)
        return system_list
    else:
        return None

def remove_systems(system_list):
    print "====> Removing Storage Systems"
    for system in system_list:
        print "Removing this one: %s" % system
        for name, sys_type in system.iteritems():
            if sys_type is "blank":
                continue
            command0 = '/opt/storageos/cli/bin/viprcli storagesystem deregister -n ' \
                    + name + ' -t ' + sys_type
            results = run_cmd(command0)
            if len(results) > 0:
                print "Results of De-registering System: %s" % results

            command1 = '/opt/storageos/cli/bin/viprcli storagesystem delete -n ' \
                + name + ' -t ' + sys_type
            results = run_cmd(command1)
            if len(results) > 0:
                print "Results of Deleting System: %s" % results

def remove_providers(providers):
    print "====> Removing Storage Providers"
    for system in providers:
        print "Removing This one: %s" % system
        command0 = '/opt/storageos/cli/bin/viprcli storageprovider delete -n ' + system 
        results = run_cmd(command0)
        if len(results) > 0:
            print "Results of Deleting Provider: %s" % results

def get_endpoints(network):
    # Remove the varray from the network first
    print "====> Getting Endpoints"
    command0 = '/opt/storageos/cli/bin/viprcli network show -n ' + network 
    results = run_cmd(command0)
    json_dump = json.loads(results)
    # Pull Endpoints
    print "Endpoints are: %s" % json_dump['endpoints']
    return(json_dump['endpoints'])
    
def remove_network(network,endpoints):
    # Remove the varray from the network first
    print "====> Getting Varray on this Network"
    command0 = '/opt/storageos/cli/bin/viprcli network show -n ' + network
    results = run_cmd(command0)
    json_dump = json.loads(results)
    if 'connected_varrays' in json_dump:
        varray = json_dump['connected_varrays'][0]
        # Remove Varray from Network
        print "Connected Varray is: %s" % varray
        print "====> Removing Varray From Network"
        command0 = '/opt/storageos/cli/bin/viprcli network update -varray_remove \
                ' + varray + ' -n ' + network
        results = run_cmd(command0)
        if len(results) > 0:
            print "Results on updating network to remove varray : %s" % results

    # De-register Network
    print "====> De-register Network"
    command1 = '/opt/storageos/cli/bin/viprcli network deregister -n ' + network
    results = run_cmd(command1)
    if len(results) > 0:
        print "Results on deregistering network : %s" % results

    # Need to remove the endpoints before removing the network
    print "====> Remove Network Endpoints"
    for endpoint in endpoints:
        command2 = '/opt/storageos/cli/bin/viprcli network endpoint remove -n '\
                     + network + ' -e ' + endpoint
        results = run_cmd(command2)
        if len(results) > 0:
            print "Results on removing endpoint: %s" % results

    print "====> Deleting Network"
    command3 = '/opt/storageos/cli/bin/viprcli network delete -n ' + network
    results = run_cmd(command3)
    if len(results) > 0:
        print "Results on removing network: %s" % results

def remove_export_groups(tenant):
    print "====> Delete Export Groups"
    project = get_project(tenant)
    if project is None:
        print "No Project, therefore No Volumes to Delete"
        return
    command0 = '/opt/storageos/cli/bin/viprcli exportgroup list -pr '+ project + ' -tn "' + tenant + '"'
    results = run_cmd(command0)
    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grab Data
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            print "====> Deleting Export Group : %s" % entry
            command = '/opt/storageos/cli/bin/viprcli exportgroup delete -n '+\
                    entry+' -pr '+ project + ' -tn "' + tenant + '"'
            results = run_cmd(command)
            if len(results) > 0:
                print "Deleting ExportGroup " + entry + " results: %s" % results
                sys.exit(-1)
    else:
        print "No Export Groups to Delete"


def remove_vols(tenant=None):
    print "====> Get Volumes"
    project = get_project(tenant)
    if project is None:
        print "No Project, therefore No Volumes to Delete"
        return
    if tenant is None:
        command0 = '/opt/storageos/cli/bin/viprcli volume list -pr '+ project
    else:
        command0 = '/opt/storageos/cli/bin/viprcli volume list -pr '+ project + ' -tn "'+tenant+'"'
    results = run_cmd(command0)
    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grap Volumes
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            print "====> Deleting Volume: %s" % entry
            command = '/opt/storageos/cli/bin/viprcli volume delete -n '+\
                    entry+' -pr '+ project
            results = run_cmd(command)
            if len(results) > 0:
                print "Deleting Volume " + entry + " results: %s" % results
                sys.exit(-1)
    else:
        print "No Volumes to Delete"

def remove_va():
    print "====> Removing Varays"
    cmd = '/opt/storageos/cli/bin/viprcli varray list'
    results = run_cmd(cmd)
    if len(results) > 0:
        result = results.split()
        for entry in result:
            if entry != "NAME":
                print "====> Deleting Varray: %s" % entry
                command = '/opt/storageos/cli/bin/viprcli varray delete -n '+entry
                results = run_cmd(command)
                if len(results) > 0:
                    print "Deleting varray " + entry + " results: %s" % results
                    sys.exit(-1)
    else:
        print "No Varrays to Delete"

def remove_vpool_database():
    print "    ---> Remove Any DB Links to Vpool"
    command = '/opt/storageos/bin/dbcli list VirtualPool'
    results = run_cmd(command)
    print "Results are: %s " % results
    if len(results) > 0:
        result = results.split('\n')
        # Find Id
        for i in result:
            test = re.search(r'^id:', i)
            if test is not None:
                taskId = (i.split(': ', 1))[1]
                print "    ---> Removing Task Id: %s" % taskId
                command = '/opt/storageos/bin/dbcli delete -i ' + taskId + ' VirtualPool'
                results = run_cmd(command)
                #print "         Results: %s" % results
                
def remove_vpool():
    print "====> Deleting VPools"
    cmd = '/opt/storageos/cli/bin/viprcli vpool list -t block'
    results = run_cmd(cmd)

    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grap Vpools
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            print "====> Deleting VPool: %s" % entry
            command = '/opt/storageos/cli/bin/viprcli vpool delete -n '+\
                    entry+' -type block'
            results = run_cmd(command)
            if len(results) > 0:
                print "Deleting Vpool " + entry + " results: %s" % results
                sys.exit(-1)
    else:
        print "No Vpools To Delete"
    remove_vpool_database()

# Returns the first project found.  For Dev-Test, hopefully only one exists
def get_project(tenant='Provider Tenant'):
    print "====> Get Project for Tenant: %s" % tenant
    cmd = '/opt/storageos/cli/bin/viprcli project list -tn "'+ tenant + '"'
    results = run_cmd(cmd)
    if len(results) > 0:
        result = results.split()
        for entry in result:
            if entry != "NAME":
                return(entry)
    else:
        print "No Projects Are Defined"
        return None

def remove_project(tenant):
    project = get_project(tenant)
    if project is None: 
        return
    print "====> Deleting Project : %s" % project
    if tenant is None:
        command = '/opt/storageos/cli/bin/viprcli project delete -n '+project
    else:
        print "    ---> Remove Any Tasks for QuotaOfCinder"
        command = '/opt/storageos/bin/dbcli list QuotaOfCinder'
        results = run_cmd(command)
	#print "Results are: %s " % results
        if len(results) > 0:
            result = results.split('\n')
            # Find TaskId
            for i in result:
                test = re.search(r'^id:', i)
		if test is not None:
		    taskId = (i.split(':'))[1]
                    print "    ---> Removing Task Id: %s" % taskId
                    command = '/opt/storageos/bin/dbcli delete -i ' + taskId + ' QuotaOfCinder'
 		    results = run_cmd(command)
		    #print "         Results: %s" % results
        command = '/opt/storageos/cli/bin/viprcli project delete -n '+project+' -tn "'+tenant+'"'
    results = run_cmd(command)
    if len(results) > 0:
        print "Deleting project " + project + " results: %s" % results
        sys.exit(-1)
    

def remove_tenant(tenant):
    print "====> Deleting Tenant: %s" % tenant
    command0 = '/opt/storageos/cli/bin/viprcli tenant delete -n '+tenant
    results = run_cmd(command0)
    if len(results) > 0:
        print "Results of Deleting Tenant: %s" % results

def remove_hosts():
    print "====> Removing Hosts"
    cmd = '/opt/storageos/cli/bin/viprcli host list'
    results = run_cmd(cmd)

    if len(results) > 0:
        result = results.split('\n')
        # Skip header row and grap hosts
        for i in range (1, len(result)-1):
            entry = (result[i].split())[0]
            host_type = (result[i].split())[2]
            print "====> Deleting Host: %s" % entry
            command = '/opt/storageos/cli/bin/viprcli host delete -n '+\
                    entry + ' -t ' + host_type
            results = run_cmd(command)
            if len(results) > 0:
                print "Deleting Host " + entry + " results: %s" % results
                sys.exit(-1)
    else:
        print "No Hosts to Delete"

def remove_key_auth():
    print "====> Deleting Keystone Auth Provider"
    command0 = '/opt/storageos/cli/bin/viprcli authentication delete-provider \
                 -n Key1'
    results = run_cmd(command0)
    if len(results) > 0:
        print "Results are: %s" % results

def get_os_projects(name):
    command0 = 'openstack project show ' + name + ' -f json'
    results = run_cmd(command0)
    json_dump = json.loads(results)
    try:
        id = json_dump['id']
        return id
    except:
        raise(Exception("No ID For Admin Project"))

def get_service(name):
    print "====> Getting Service for volumev2"
    command0 = 'openstack service show ' + name + ' -f json'
    results = run_cmd(command0)
    json_dump = json.loads(results)
    try:
        id = json_dump['id']
        return id
    except:
        raise(Exception("No ID For Admin Project"))

def get_os_endpoint(name):
    command0 = 'openstack endpoint show ' + name + ' -f json'
    results = run_cmd(command0)
    json_dump = json.loads(results)
    try:
        id = json_dump['id']
        return id
    except:
        raise(Exception("No ID For Admin Project"))

def restore_os_endpoint(service_id):
    print "====> Restoring Endpoint for Cinder in OpenStack"
    # Pull IP and Port from OS_AUTH_URL setting
    os_url = config.os_auth_url
    os_url = os_url.replace("http://","")
    os_url = os_url.split('/')[0]
    (os_url, os_port) = os_url.split(':')
    os_port = int(os_port)
    command0 = 'openstack endpoint create ' + service_id + ' --publicurl=http://'+os_url+':8776/v2/$\(tenant_id\)s --adminurl=http://'+os_url+':8776/v2/$\(tenant_id\)s --internalurl=http://'+os_url+':8776/v2/$\(tenant_id\)s --region=RegionOne'
    #print "Restoring Command: %s" % command0
    results = run_cmd(command0)
    if len(results) > 0 and args.verbose:
        print "Results from executing endpoint create for Cinder: "
	print "%s" % results

def create_os_endpoint_for_ch(service_id):
    print "====> Creating Endpoint for CoprHD in OpenStack"
    command0 = 'openstack endpoint create ' + service_id + ' --publicurl=http://'+config.coprhd_host+':8080/v2/$\(tenant_id\)s --adminurl=http://'+config.coprhd_host+':8080/v2/$\(tenant_id\)s --internalurl=http://'+config.coprhd_host+':8080/v2/$\(tenant_id\)s --region=RegionOne'
    results = run_cmd(command0)
    if len(results) > 0:
        print "Results from executing endpoint create for CH: "
	print "%s" % results

def delete_os_endpoint(id):
    print "====> Deleting OpenStack Endpoint"
    command0 = 'openstack endpoint delete ' + id
    results = run_cmd(command0)
    if len(results) > 0:
        print "Results of endpoint delete: %s" % results

def add_tenant_id(pid):
    print "====> Adding Tenant"
    command0 = '/opt/storageos/cli/bin/viprcli -hostname '+ config.coprhd_host+' tenant create -n admin -domain lab -key tenant_id -value ' + pid
    results = run_cmd(command0)
    if len(results) > 0:
        print "Results from add_tenant: %s" % results

def create_project_for_scaleio_only():

    print "====> Creating TestProject Project"
    cmd = '/opt/storageos/cli/bin/viprcli project create -n TestProject -hostname ' + config.coprhd_host
    results = run_cmd(cmd)
    if len(results) > 0:
        print "Results are: %s" % results

def create_project_for_devstack():
    print "====> Creating Admin Project"
    cmd = '/opt/storageos/cli/bin/viprcli project create -n admin -tn admin -hostname ' + config.coprhd_host
    results = run_cmd(cmd)
    if len(results) > 0:
        print "Results are: %s" % results

def tag_project(project_id):
    print "====> Tagging Admin Project"
    command0 = '/opt/storageos/cli/bin/viprcli project tag -hostname ' + config.coprhd_host + ' -n admin -tn admin -add ' + project_id
    results = run_cmd(command0)
    if len(results) > 0:
        print "Results are: %s" % results

def check_auth_config():
    command0 = 'grep -c "url:$" auth_config.cfg'
    data = int(pexpect.run(command0).rstrip())
    # Non-zero means url is blank
    if data != 0:
        escaped_url = re.escape(config.os_auth_url)
        command1 = ("sed -i 's/url:/url:"+escaped_url+"/' auth_config.cfg")
        data = run_cmd(command1)
        escaped_password = re.escape(config.os_password)
        command2 = ("sed -i 's/passwd_user:/passwd_user:"+escaped_password+"/' auth_config.cfg")
        data = run_cmd(command2)

def os_integration():
    """OS Integration adds the OpenStack pieces into CH and 
        adds the CH Endpoint into OS Keystone"""
    check_auth_config()
    add_keystone_auth()
    os_project_id = get_os_projects('admin')
    add_tenant_id(os_project_id)
    # Add CH Project with admin tenant
    create_project_for_devstack()
    tag_project(os_project_id)
    # Remap Volume service to CH
    service_id = get_service('volumev2')
    endpoint_id = get_os_endpoint('volumev2')
    delete_os_endpoint(endpoint_id)
    create_os_endpoint_for_ch(service_id)

# Check MDM1 is running
def check_mdm1():
    print "====> Checking that ScaleIO is up...."
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Pull IP and Port from OS_AUTH_URL setting
    os_url = config.scaleio_mdm1_ip
    os_port = 22
    try:
        s.connect((os_url, os_port))
        print "MDM1 Node is up"
    except socket.error as e:
        print "Error connecting to MDM1: %s" % e
        print "Make sure ScaleIO is running!"
        sys.exit(-1)
    finally:
        s.close()

# Check if DevStack VM is running
def check_devstack():
    print "====> Checking that DevStack is up...."
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Pull IP and Port from OS_AUTH_URL setting
    os_url = config.os_auth_url
    os_url = os_url.replace("http://","")
    os_url = os_url.split('/')[0]
    (os_url, os_port) = os_url.split(':')
    os_port = int(os_port)
    try:
        s.connect((os_url, os_port))
        print "DevStack Node is up"
    except socket.error as e:
        print "Error connecting to DevStack: %s" % e
        print "Make sure DevStack is running!"
        sys.exit(-1)
    finally:
        s.close()

def coprhd_os_setup():
    if get_storage_providers() is not None:
        print "Storage Providers already configured. Cowardly not setting up again"
        print "Run coprhd -d to clear out setup"
        sys.exit(-1)
    check_devstack()
    os_integration()
    # Setup CoprHD
    set_provider()    
    networks = get_networks(20)
    # Only setup ScaleIO Network for VA
    if networks is None:
        print "Error - No Network - Abort!"
        sys.exit(-1)
    else:
        for network in networks:
            test = re.search(r'\w+-ScaleIONetwork', network)
            if test is not None:
                print "ScaleIO Network Found: %s" % network
                create_va(network)
                create_vp()
    # Don't create vol - tenant can't be deleted if vol is created
    # create_vol()

def coprhd_scaleio_only():
    if get_storage_providers() is not None:
        print "Storage Providers already configured. Cowardly not setting up again"
        print "Run coprhd -d to clear out setup"
        sys.exit(-1)
    check_mdm1()
    create_project_for_scaleio_only()
    # Setup CoprHD
    set_provider()
    networks = get_networks(20)
    # Only setup ScaleIO Network for VA
    if networks is None:
        print "Error - No Network - Abort!"
        sys.exit(-1)
    else:
        for network in networks:
            test = re.search(r'\w+-ScaleIONetwork', network)
            if test is not None:
                print "ScaleIO Network Found: %s" % network
                create_va(network)
                create_vp()

def coprhd_delete():
    tenant = get_tenant()
    networks = get_networks(retry=2)
    if networks is None:
        print "No Network to delete"
    else:
        for network in networks:
            remove_export_groups(tenant)
            endpoints = get_endpoints(network)
            remove_network(network,endpoints)
    # If there were vols, we can't remove tenants
    remove_vols(tenant)
    remove_vpool()
    remove_va()
    remove_hosts()
    remove_project(tenant)
    # If volumes were created, you cannot remove tenant
    if tenant != 'Provider Tenant':
        remove_tenant(tenant)
        remove_key_auth()
    systems = get_storage_systems()
    if systems is None:
        print "No Storage System to Delete"
    else:
        remove_systems(systems)
    providers = get_storage_providers()
    if providers is None:
        print "No Storage Providers to Delete"
    else:
        remove_providers(providers)
    if tenant != 'Provider Tenant':
        print "Deleting Endpoint of Volumev2"
        endpoint_id = get_os_endpoint('volumev2')
        delete_os_endpoint(endpoint_id)
        service_id = get_service('volumev2')
        restore_os_endpoint(service_id)


def coprhd_check(project='admin', tenant='admin'):
    print "====> Storage Provider(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli storageprovider list')
    print run_cmd(command0)

    print "====> Storage System(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli storagesystem list')
    print run_cmd(command0)

    print "====> Network(s)"
    networks = get_networks(retry=2)
    if networks is not None:
        print networks

    print "====> Virtual Array(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli varray list')
    print run_cmd(command0)

    print "====> Virtual Pool(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli vpool list -t block')
    data = run_cmd(command0)
    print data
    if len(data) > 0:
        print "====> Volume(s) for Project: " + project + ", Tenant: "+tenant
        command0 = '/opt/storageos/cli/bin/viprcli volume list -pr '+project+\
                ' -tn "' + tenant +'"'
        print run_cmd(command0)

    print "====> Authentication Provider(s)"
    command0 = ('/opt/storageos/cli/bin/viprcli authentication list-providers')
    data = run_cmd(command0)
    print data

def run_cmd(cmd):
    results = ''
    command = shlex.split(cmd)
    #print "Debug: command is: %s" % command
    try:
        results = subprocess.check_output(command, stderr=err_file)
    except subprocess.CalledProcessError as e:
        pass
        #print "Error on call: message: %s, error: %s" % (e.message, e)
        #print "Results are: %s" % results

    return results

if __name__ == "__main__":
    check_auth_config()
    args = init()
    login()
    if args.setup:
	coprhd_scaleio_only()
    elif args.delete:
        coprhd_delete()
    elif args.check:
        tenant = get_tenant()
        print "Tenant is: %s" % tenant
        project = get_project(tenant)
        coprhd_check(project=project, tenant=tenant)
    elif args.openstack:
	coprhd_os_setup()


