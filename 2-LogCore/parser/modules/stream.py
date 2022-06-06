import logging
import sys

log = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
class Stream(object):

    def __init__(self, filename):
        self.stream = open(filename, 'w')


    def write(self, event):
        if event.is_corrupted():
            log.warn("Log entry {0} is corrupted.".format(event.__str__()))
            return
        self.stream.write(event.__str__() + "\n")


