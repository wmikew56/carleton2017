import os
import fcntl


class dpflock(object):
    
    def __init__(self, path, flags=os.O_RDWR, mode=0o600):
        self.fd = os.open(path, flags, mode)
        fcntl.flock(self.fd, fcntl.LOCK_EX)

    @classmethod
    def lock(cls, path, flags=os.O_RDWR, mode=0o600):
        return cls(path, flags, mode)

    def __enter__(self):
        return self.fd

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.close(self.fd)
