import sys

import interp


class PlyaraParser:

    def parseString(self, inputString):
        return interp.parseString(inputString)

    def parseFromFile(self, filePath):

        f = open(filePath, 'r')
        inputString = f.read()
        return(self.parseString(inputString))


def main():
    if len(sys.argv) != 2:
        sys.stderr.write('\nUsage is ' + sys.argv[0] + ' [file_to_parse].  Exiting')
        sys.exit(1)

    p = PlyaraParser()
    print(p.parseFromFile(sys.argv[1]))


if __name__ == "__main__":
    main()
