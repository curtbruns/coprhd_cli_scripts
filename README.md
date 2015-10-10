# coprhd_cli_scripts
CoprHD Cli (viprcli) scripts to setup and teardown for Testing via Command line

## Prerequisites
1. Devstack setup (can use this one: https://github.com/curtbruns/devstackKilo)
2. CoprHD with Cinder API integration (https://github.com/CoprHD/CoprHD.github.io) branch: feature-cinderapi
* Use the vagrant box (https://github.com/vchrisb/vagrant-coprhd) to get started and re-build the feature-cinderapi branch
3. ScaleIO Cluster (https://github.com/jonasrosland/vagrant-scaleio)
4. Vagrant
5. Virtualbox

##Execution Flow
1. vagrant up the Devstack box
2. vagrant up the ScaleIO box
3. vagrant up the CoprHD box
4. On the CoprHD VM:
* % python os_integration.py
* % python coprhd_setup.py
* You've now setup Devstack to point to CoprHD for VolumeV2 operations
* The admin tenant/project on Devstack points to the Admin Tenant/Project on CoprHD

## Test It
1. Create a 1GB Volume in Cinder in the CoprHD Virtual Pool (VP1), which is mapped as a volume type in Cinder
* % cinder --debug create --volume-type VP1 --name CinderTest 1
* You should see the CinderTest volume created in both the CorpHD GUI and Cinder List and Horizon 


