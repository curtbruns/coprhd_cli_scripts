import os

# CoprHD Settings
root_password = os.getenv('ROOT_PASSWORD')
coprhd_host = os.getenv('COPRHD_HOST')
coprhd_password = os.getenv('COPRHD_PASSWORD')

# OpenStack Settings
os_password = os.getenv('OS_PASSWORD')
os_auth_url = os.getenv('OS_AUTH_URL')
os_username = os.getenv('OS_USERNAME')
os_tenant_name = os.getenv('OS_TENANT_NAME')

# ScaleIO Settings
scaleio_password = os.getenv('SCALEIO_PASSWORD')
scaleio_mdm1_ip  = os.getenv('SCALEIO_MDM1_IP')
scaleio_mdm2_ip  = os.getenv('SCALEIO_MDM2_IP')
scaleio_tb_ip    = os.getenv('SCALEIO_TB_IP')

# CEPH Settings
ceph_mon_ip      = os.getenv('MON_IP')
admin_key        = os.getenv('ADMIN_KEY')
