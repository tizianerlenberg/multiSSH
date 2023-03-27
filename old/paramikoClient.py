import paramiko.client
import hostKeys

class SSHClient(paramiko.client.SSHClient):
    def __init__(self):
        self._system_host_keys = paramiko.client.HostKeys()
        
        # LINE CHANGED FROM ORIGINAL
        self._host_keys = hostKeys.HostKeys()

        self._host_keys_filename = None
        self._log_channel = None
        self._policy = paramiko.client.RejectPolicy()
        self._transport = None
        self._agent = None
    
    def load_host_keys_from_string(self, keys):
        self._host_keys.load_from_string(keys)

