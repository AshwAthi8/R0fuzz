from core.logger import get_logger

from core.extract import Extractor
#from core.dumb_fuzzing import *

# Default imports 
import argparse
import os
import sys
from colorama import init
from termcolor import cprint 
from pyfiglet import figlet_format

class r0fuzz(object):

    def __init__(self, seed, protocol, dumbool, log_level):
        self.seed = os.path.join(os.getcwd(), seed)
        self.protocol = protocol
        self.dumb = dumbool
        self.log_level = log_level

        self.extractor = Extractor(self)

        if not self._sanity_check():
            logging.critical("[+] r0fuzz failed to init")
            sys.exit(-1)

    def _sanity_check(self) -> bool:
        """Verify the arguments passed"""

        if not os.path.isfile(self.seed):
            logging.error("[+] The seed file is not found at %s", self.seed)
            return False
        logging.debug("[+] The input file is at %s", self.seed)
        return True

def main():
    global logging

    init(strip=not sys.stdout.isatty()) # strip colors if stdout is redirected
    cprint(figlet_format('r0fuzz', font='starwars'),'yellow', attrs=['bold'])

    parser = argparse.ArgumentParser(description="A grammar based fuzzer for SCADA protocols")

    parser.add_argument("-s", "--seed", help="sample input file", type=str, required=True)
    parser.add_argument("-t", "--target", help="target protocol", type=str, required=True)
    parser.add_argument("-d", "--dumb", help="Dumb fuzz the target", action="store_true")
    parser.add_argument("-v", "--verbosity", help="Log level", action="count")
    args = parser.parse_args()

    logging = get_logger("r0fuzz", args.verbosity)

    r0obj = r0fuzz(args.seed, args.target, args.dumb, args.verbosity)

    r0obj.extractor.generate_fields()
    logging.info('[+] Generated fields')

    if r0obj.dumb:
        print("Dumb fuzz")
    else:
        print("grammar fuzz")

if __name__ == "__main__":
    logging = None
    main()

    