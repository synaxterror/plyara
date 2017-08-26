import argparse

import interp


class PlyaraParser:

    def parseString(self, inputString):
        return interp.parseString(inputString)

    def parseFromFile(self, filePath):

        f = open(filePath, 'r')
        inputString = f.read()
        return(self.parseString(inputString))


def main():
    """Run main function."""
    parser = argparse.ArgumentParser(description='Parse Yara rules into a dictionary representation.')
    parser.add_argument('file', metavar='FILE', help='File containing YARA rules to parse.')
    args, _ = parser.parse_known_args()

    p = PlyaraParser()
    print(p.parseFromFile(args.file))


if __name__ == "__main__":
    main()
