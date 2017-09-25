#!/usr/bin/env python

import argparse
import r2pipe as r2p


def get_args():
    parser = argparse.ArgumentParser(description=("Simple analysis and human friendly "
                                                  "renames of any function/local"))

    args = parser.parse_args()

    return args


def renameit(directory):
    r = r2p.open()


def main():
    args = get_args()

    renameit()


if __name__ == "__main__":
    main()
