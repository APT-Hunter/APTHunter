
class Event(object):

    def __init__(self, ts, subj, sc, ino, fname):

        self.ts = ts
        self.subj = subj
        self.sc = sc
        self.ino = ino
        self.fname = fname

    def is_corrupted(self):
       """ Verify the entry is not corrupted."""
       if None in [self.ts, self.subj, self.sc, self.ino, self.fname]:
           return True
       else:
           return False


    def __str__(self):

        return "{0},{1},{2},{3},{4}".format(
            self.ts,
            self.subj,
            self.sc,
            self.ino,
            self.fname
        )



