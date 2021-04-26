# ---------------------------------------------------------------
# Encrypted Search Query Analysis By Eavesdropping (ESQABE)
# Copyright (C) 2021  Isaac Meers (Hasselt University/EDM)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Please cite the paper if you are using this source code.
# ---------------------------------------------------------------

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