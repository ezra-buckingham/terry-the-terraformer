import sys
  
# setting path
sys.path.append('../terry')

from handlers import *

root_dir = "/Users/quaiddelacluyse/Desktop/repositories/terry/deployments"
deployment = "quaid_testing"

file = open(f'{root_dir}/{deployment}/{deployment}_key', "rb")
byte = file.read(1)
key = b''
while byte:
    key += byte
    byte = file.read(1)

ansible_handler = AnsibleHandler(ssh_key=key, working_dir=f"{root_dir}/{deployment}/ansible")
wait_playbook = '../../../core/playbooks/wait-for-system-setup.yml'
prep_playbook = '../../../core/playbooks/prep-all-systems.yml'
playbook = '../../../core/playbooks/setup-teamserver.yml'

# ansible_handler.run_playbook('admin', wait_playbook, {'provider': 'aws'}, '18.220.189.207')
# ansible_handler.run_playbook('admin', prep_playbook, {}, '18.220.189.207')
ansible_handler.run_playbook(playbook)

