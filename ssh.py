#
# Remote ssh cmds
#

import pty, re, os, sys, stat, getpass

class SSHError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class SSH: 
    def __init__(self, ip, passwd, user, port):
        self.ip = ip
        self.passwd = passwd
        self.user = user
        self.port = port

    def run_cmd(self, c):
        (pid, f) = pty.fork()
        if pid == 0:
            os.execlp("ssh", "ssh", '-p %d' % self.port,
                      self.user + '@' + self.ip, c)
        else:
            return (pid, f)     

    def push_file(self, src, dst):
        (pid, f) = pty.fork()
        if pid == 0:
            os.execlp("scp", "scp", '-P %d' % self.port,
                      src, self.user + '@' + self.ip + ':' + dst)
        else:
            return (pid, f) 

    def pull_file(self, src, dst):
        (pid, f) = pty.fork()
        if pid == 0:
            os.execlp("scp", "scp", '-P %d' % self.port,
                       self.user + '@' + self.ip + ':' + src, dst)
        else:
            return (pid, f) 

    def push_dir(self, src, dst):
        (pid, f) = pty.fork()
        if pid == 0:
            os.execlp("scp", "scp", '-P %d' % self.port, "-r", src,
                      self.user + '@' + self.ip + ':' + dst)
        else:
            return (pid, f)

    def _read(self, f):
        x = ''
        try:
            x = os.read(f, 1024)
        except Exception, e:
            # this always fails with io error
            pass
        return x

    def ssh_results(self, pid, f):
        output = ""
        got = self._read(f)         # check for authenticity of host request
        m = re.search("authenticity of host", got)
        if m:
            os.write(f, 'yesn') 
            # Read until we get ack
            while True:
                got = self._read(f)
                m = re.search("Permanently added", got)
                if m:
                    break

            got = self._read(f)         # check for passwd request
        m = re.search("assword:", got)
        if m:
            # send passwd
            os.write(f, self.passwd + 'n')
            # read two lines
            tmp = self._read(f)
            tmp += self._read(f)
            m = re.search("Permission denied", tmp)
            if m:
                raise Exception("Invalid passwd")
            # passwd was accepted
            got = tmp
        while got and len(got) > 0:
            output += got
            got = self._read(f)
        os.waitpid(pid, 0)
        os.close(f)
        return output

    def cmd(self, c):
        (pid, f) = self.run_cmd(c)
        return self.ssh_results(pid, f)

    def pull(self, src, dst):
        (pid, f) = self.pull_file(src, dst)
        return self.ssh_results(pid, f)

    def push(self, src, dst):
        s = os.stat(src)
        if stat.S_ISDIR(s[stat.ST_MODE]):
            (pid, f) = self.push_dir(src, dst)
        else:
            (pid, f) = self.push_file(src, dst)
        return self.ssh_results(pid, f)

def ssh_cmd(ip, passwd, cmd, user=getpass.getuser(), port=22):
    s = SSH(ip, passwd, user, port)
    return s.cmd(cmd)

def ssh_push(ip, passwd, src, dst, user=getpass.getuser(), port=22): 
    s = SSH(ip, passwd, user, port)
    return s.push(src, dst)