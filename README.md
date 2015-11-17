# coprhd_cli_scripts
CoprHD Cli (viprcli) scripts to setup and teardown for testing via command-line

## Prerequisites
1. All-in-one Vagrant setup (https://github.com/curtbruns/coprhd_aio) which includes Devstack, ScaleIO and CoprHD
2. This repo will be cloned as part of Pre-req 1 in /opt/storageos/coprhd_cli_scripts
3. Modify coprhd_settings file to match your environment (IPs, Passwords, etc)

##Execution Flow
* Make sure coprhd_settings matches your environment
* Source the coprhd_settings file
* Check coprhd seteup:
  * ./coprhd -c 
* Register Keystone as Auth provider, Setup ScaleIO as Storage Provider, Create VPool, VArray, Project, Tenant, and update Devstack to use CoprHD as Volume Service:
  * ./coprhd -s
* Delete all traces of CoprHD setup (remove Auth provider, VPool, Varray, Project, Tenant)
  * ./coprhd -d
  * Note: This doesn't revert the Keystone Endpoint back to Using Cinder as VolumeV2 service
* Partial Setup (Only Add ScaleIO as backend with Varray/Vpool and Project setup - no Devstack/Keystone changes or Auth provider added)
  * ./coprhd -p
