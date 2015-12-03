# coprhd_cli_scripts
CoprHD Cli (viprcli) scripts to setup and teardown for testing via command-line

## Prerequisites
1. All-in-one Vagrant setup (https://github.com/curtbruns/coprhd_aio) which includes VMs for Devstack, ScaleIO and CoprHD
2. This repo will be cloned as part of Pre-req 1 in /opt/storageos/coprhd_cli_scripts
3. Modify coprhd_settings file to match your environment (IPs, Passwords, etc)

##Execution Flow
* Make sure coprhd_settings matches your environment (Passwords, URLs, etc)
* Source the coprhd_settings file
* Choose your desired Config below - either Config1 or Config2

## Config1: CoprHD Setup with ScaleIO (Easy Button)
* ./coprhd -s
* This will add: ScaleIO as a Storage Provider/Backend, ScaleIO network, Virtual Array and Create a ThickSATA Virtual Pool

## Config2: CoprHD Setup with ScaleIO and Devstack and Keystone as Auth Provider
* ./coprhd -o
* This will perform everything in the (Easy Button) step, plus:
* Register Keystone as Auth provider
* Add Admin Tenant and Project
* Update Devstack to use CoprHD as Volume Service

## Tear Everything Down
* ./coprhd -d
* This will delete all traces of CoprHD setup (remove Auth provider, VPool, Varray, Project, Tenant)
  * Note: This doesn't revert the Keystone Endpoint back to Using Cinder as VolumeV2 service

## Check CoprHD Setup
* ./coprhd -c 
