#! /usr/bin/env python3
import os
import re
import subprocess
import sys
import paramiko

pemdir = "pemkeys/"


def format_output(output, regex=None):
    assert type(output)==list, 'the output parameter need to be a list'

    if not regex:
        output.pop()
        return output

    data = list()
    pattern = re.compile(regex)
    for line in output:
        match = pattern.search(line)
        if match:
            if pattern.groups > 0:
                set = list()
                for i in range(0, pattern.groups):
                    if match.group(i + 1) is not None:
                        set.append(match.group(i + 1))
                data.append(set)
            else:
                data.append(line)

    return data


def shell_output(command, regex=None):
    output = subprocess.check_output(command)
    lines = output.decode().split('\n')
    return format_output(lines, regex)


def rm_oldfiles(newfile):
    oldfiles = shell_output(['ls', pemdir],
                            r'([A-Za-z0-9-]+)(\.txt)$|([A-Za-z0-9-]+)(\.pem$)|([A-Za-z0-9-]+)(\.\w+:\w+\.+Identifier)$')
    for file in oldfiles:
        if not newfile == file[0]:
            subprocess.run(['rm', pemdir + file[0] + file[1]])
            print("removed " + file[0] + file[1])
    print("Pem keys change detected, pemkeys directory has been cleared")


# This function get the last .pem file modified in pemdir directory
# if there isn't directory the program makes it
def pem_find():
    if not os.path.exists(pemdir):
        os.mkdir(pemdir)

    target = shell_output(["ls", pemdir, "-lt"], r'\d\s([\w-]+)\.pem$')
    if not target:
        raise FileNotFoundError("No .pem file founded in directory")
    else:
        return target[0]


# this function check if there is a temp file where read the information needed
# for login, if you add new .pem in the directory the temp will be removed
def get_accessdata(file):
    if not os.path.exists(pemdir + "temp" + file + ".txt"):
        # if there isn't the temp file that we are searching for, then remove old and
        # make another one
        ip = input("Insert IP:")
        username = input("Insert Username:")
        line = ip + ' ' + username
        rm_oldfiles(file)
        with open(pemdir + "temp" + file + ".txt", 'w+') as temp:
            temp.write(line)
        return ip, username
    else:
        # else just read it
        with open(pemdir + "temp" + file + ".txt") as temp:
            line = temp.readline().split()
        return line[0], line[1]

pemfile = pem_find()[0]
try:
    if(sys.argv[1]=='-shell'):
        ip, username = get_accessdata(pemfile)
        command='sudo ssh -i {} {}@{}'.format(pemdir+pemfile+'.pem',username,ip).split()
        subprocess.run(command)
    else:
        print('Parameter not recognized')
except IndexError:
    ip, username = get_accessdata(pemfile)
    k = paramiko.RSAKey.from_private_key_file(pemdir + pemfile + '.pem')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("connecting to host")
    ssh.connect(hostname=ip, username=username, pkey=k)
    print("connected")
    for command in sys.stdin:
        if (command == '\exit/'):
            ssh.close()
            break
        else:
            stdin, stdout, stderr = ssh.exec_command(command)
            error = stderr.read()
            if not error:
                print(format_output(stdout.read().decode().split('\n')))
            else:
                print(error.decode())