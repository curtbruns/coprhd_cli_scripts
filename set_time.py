import sys
import os
from subprocess import call
from subprocess import check_output

#print os.environ
output = check_output(["date"])
print "Date is: %s" % output

call(["sudo", "service", "ntpd", "stop"])

if os.getenv('http_proxy'):
    print "Proxy set - setting time with Intel NTP Server"
    call(["sudo", "ntpdate", "-s", "10.3.3.251"])
else:
    print "No proxy - using gov time server"
    call(["sudo", "ntpdate", "-s", "time.nist.gov"])
    
call(["sudo", "service", "ntpd", "start"])
print "Now date is: %s" % (check_output(["date"]))

print "Done!"

