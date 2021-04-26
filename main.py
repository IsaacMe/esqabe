import argparse
import sys
from esqabe import esqabe


def main():
    """
    ESQABE main function, parsers commandline parameters and runs!
    :return: None
    """
    args = sys.argv[1:]

    parser = argparse.ArgumentParser(prog='ESQABE', description='Determine what was Googled from a Wireshark'
                                                                       ' capture where HTTPS was used!')
    parser.add_argument('pcapng', type=str, help='filename of the pcapng trace')

    args = parser.parse_args(args)
    esqabe(**vars(args))


if __name__ == '__main__':
    main()