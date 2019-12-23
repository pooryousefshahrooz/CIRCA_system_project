#!/usr/bin/python

import os
import sys
import select
#import paramiko
import time


class Commands:
    def __init__(self, retry_time=0):
        self.retry_time = retry_time
        pass

    def run_cmd(self, host_ip, cmd_list):
        i = 0
        while True:
        # print("Trying to connect to %s (%i/%i)" % (self.host, i, self.retry_time))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host_ip)
                break
            except paramiko.AuthenticationException:
                print("Authentication failed when connecting to %s" % host_ip)
                sys.exit(1)
            except:
                print("Could not SSH to %s, waiting for it to start" % host_ip)
                i += 1
                time.sleep(2)

            # If we could not connect within time limit
            if i >= self.retry_time:
                print("Could not connect to %s. Giving up" % host_ip)
                sys.exit(1)
            # After connection is successful
            # Send the command
            for command in cmd_list:
                # print command
                print "> " + command
                # execute commands
                stdin, stdout, stderr = ssh.exec_command(command)
                # TODO() : if an error is thrown, stop further rules and revert back changes
                # Wait for the command to terminate
                while not stdout.channel.exit_status_ready():
                    # Only print data if there is data to read in the channel
                    if stdout.channel.recv_ready():
                        rl, wl, xl = select.select([ stdout.channel ], [ ], [ ], 0.0)
                        if len(rl) > 0:
                            tmp = stdout.channel.recv(1024)
                            output = tmp.decode()
                            print output

            # Close SSH connection
            ssh.close()
            return

def main(args=None):
    if args is None:
        print "arguments expected"
    else:
        import os
        import time
        source = os.getcwd()+'/'+args[0]

        target_dir = os.getcwd()
        import shutil
        shutil.make_archive(args[1], 'zip', source)
        os.system("scp "+args[1]+'.zip '+args[2]+':/etc/quagga')
        print 'we moved'
        #ssh nodee.simple.routing.emulab.net. / shell.sh
        #os.system("ssh " + args[2] + ' chmod 777 /etc/quagga/shell.sh')
        #print 'we are after chmod'
        #os.system("ssh " + args[2] + '   /etc/quagga/shell.sh')

        #os.system('scp  topology_for_testing_withdraw_delay/bgpd*.conf topology_for_testing_withdraw_delay/AStoIP.info '+args[2]+':/etc/quagga')
        

        # os.system("ssh " + args[2] + ' sudo  /etc/quagga/clear.sh')
        # os.system("ssh " + args[2] + ' sudo  /etc/quagga/createBbgDaemons.sh')
        # time.sleep(1)
        # os.system("ssh " + args[2] + ' sudo  /etc/quagga/update_withdraw_triggering.sh')
        # time.sleep(1)
        # os.system("ssh " + args[2] + ' sudo  cat /etc/quagga/bgpd10.conf.log')

if __name__ == "__main__":
    main(sys.argv[1:])