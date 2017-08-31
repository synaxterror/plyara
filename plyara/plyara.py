import argparse
import json

from plyara import interp


def plyara_parser(input_string, console_logging=False):
    return interp.parse_string(input_string, console_logging=console_logging)


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse Yara rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    parser.add_argument('--log', help='Enable debug logging to the console.', action='store_true')
    args, _ = parser.parse_known_args()

    with open(args.file, 'r') as fh:
        input_string = fh.read()

    rules = plyara_parser(input_string, console_logging=args.log)
    print(json.dumps(rules, sort_keys=True, indent=4))


if __name__ == '__main__':
    main()
