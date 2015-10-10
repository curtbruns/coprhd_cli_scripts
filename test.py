import pexpect

child = pexpect.spawn('ls -l')
child.expect(pexpect.EOF)
print child.before

child.sendline('pwd')
child.expect(pexpect.EOF)
print child.before

