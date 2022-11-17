import paramiko.hostkeys

class HostKeys(paramiko.hostkeys.HostKeys):
    def load_from_string(self, keys):
        lineno=0
        for line in keys.split('\n'):
            lineno = lineno + 1
            if (len(line) == 0) or (line[0] == "#"):
                continue
            try:
                e = paramiko.hostkeys.HostKeyEntry.from_line(line, lineno)
            except paramiko.hostkeys.SSHException:
                continue
            if e is not None:
                _hostnames = e.hostnames
                for h in _hostnames:
                    if self.check(h, e.key):
                        e.hostnames.remove(h)
                if len(e.hostnames):
                    self._entries.append(e)
