import argparse
import json

import interp


class PlyaraParser:

    def __init__(self, console_logging=False):
        self.console_logging = console_logging

    def parseString(self, inputString):
        return interp.parseString(inputString, console_logging=self.console_logging)

    def parseFromFile(self, filePath):

        f = open(filePath, 'r')
        inputString = f.read()
        return(self.parseString(inputString))


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse Yara rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args, _ = parser.parse_known_args()

    p = PlyaraParser(console_logging=args.log)
    print(json.dumps(p.parseFromFile(args.file), sort_keys=True, indent=4))


if __name__ == '__main__':
    main()
