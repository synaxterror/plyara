import argparse
import json

import interp


def plyara_parser(inputString, console_logging=False):
    return interp.parseString(inputString, console_logging=console_logging)


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse Yara rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args, _ = parser.parse_known_args()

    with open(args.file, 'r') as fh:
        inputString = fh.read()

    rules = plyara_parser(inputString, console_logging=args.log)
    print(json.dumps(rules, sort_keys=True, indent=4))


if __name__ == '__main__':
    main()
