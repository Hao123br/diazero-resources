import re

class LogProcessor:
    def __init__(self, script_name):
        self.script_name = script_name

    def process_log_line(self, line):
        if "[cowrie.ssh.factory.CowrieSSHFactory] New connection" in line:
            return self.process_cowrie_ssh_factory(line)
        elif "[HoneyPotSSHTransport," in line:
            return self.process_honeypot_ssh_transport(line)
        elif "[SSHChannel session (" in line:
            return self.process_sshchannel_session(line)
        return None

    def process_cowrie_ssh_factory(self, line):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z) \[cowrie.ssh.factory.CowrieSSHFactory\] New connection: (\d+\.\d+\.\d+\.\d+):(\d+) \((\d+\.\d+\.\d+\.\d+):(\d+)\) \[session: (\w+)\]'
        match = re.search(pattern, line)
        if match:
            return f"{match.group(1)} {self.script_name}: event_type=cowrie.ssh.factory.CowrieSSHFactory, event_description=New connection, srcip={match.group(2)}, srcport={match.group(3)}, dstip={match.group(4)}, dstport={match.group(5)}, session_id={match.group(6)}"

    def process_honeypot_ssh_transport(self, line):
        if "Remote SSH version" in line:
            return self.process_honeypot_ssh_remote_ssh_version(line)
        elif "SSH client hassh fingerprint" in line:
            return self.process_honeypot_ssh_hassh_fingerprint(line)
        elif "login attempt" in line:
            return self.process_honeypot_ssh_login_attempt(line)

    def process_honeypot_ssh_remote_ssh_version(self, line):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z) \[HoneyPotSSHTransport,(\d+),(\d+\.\d+\.\d+\.\d+)\] Remote SSH version: (\S+)'
        match = re.search(pattern, line)
        if match:
            return f"{match.group(1)} {self.script_name}: event_type=HoneyPotSSHTransport, event_description=Remote SSH version, srcip={match.group(3)}, srcport={match.group(2)}, ssh_version={match.group(4)}"

    def process_honeypot_ssh_hassh_fingerprint(self, line):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z) \[HoneyPotSSHTransport,(\d+),(\d+\.\d+\.\d+\.\d+)\] SSH client hassh fingerprint: (\S+)'
        match = re.search(pattern, line)
        if match:
            return f"{match.group(1)} {self.script_name}: event_type=HoneyPotSSHTransport, event_description=SSH client hassh fingerprint, srcip={match.group(3)}, srcport={match.group(2)}, hash_fingerprint={match.group(4)}"

    def process_honeypot_ssh_login_attempt(self, line):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z) \[HoneyPotSSHTransport,(\d+),(\d+\.\d+\.\d+\.\d+)\] login attempt \[b\'(.+?)\'/b\'(.+?)\'\] (\w+)'
        match = re.search(pattern, line)
        if match:
            return f"{match.group(1)} {self.script_name}: event_type=HoneyPotSSHTransport, event_description=login attempt, srcip={match.group(3)}, srcport={match.group(2)}, username={match.group(4)}, password={match.group(5)}, status={match.group(6)}"

    def process_sshchannel_session(self, line):
        if "CMD:" in line:
            return self.process_sshchannel_session_cmd(line)
        elif "Command found:" in line:
            return self.process_sshchannel_session_command_found(line)

    def process_sshchannel_session_cmd(self, line):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z) \[SSHChannel session \(0\) on SSHService b\'ssh-connection\' on HoneyPotSSHTransport,(\d+),(\d+\.\d+\.\d+\.\d+)\] CMD: (.+)'
        match = re.search(pattern, line)
        if match:
            return f"{match.group(1)} {self.script_name}: event_type=SSHChannel session, event_description=CMD, srcip={match.group(3)}, srcport={match.group(2)}, cmd={match.group(4)}"

    def process_sshchannel_session_command_found(self, line):
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z) \[SSHChannel session \(0\) on SSHService b\'ssh-connection\' on HoneyPotSSHTransport,(\d+),(\d+\.\d+\.\d+\.\d+)\] Command found: (.+)'
        match = re.search(pattern, line)
        if match:
            return f"{match.group(1)} {self.script_name}: event_type=SSHChannel session, event_description=Command found, srcip={match.group(3)}, srcport={match.group(2)}, cmd={match.group(4)}"