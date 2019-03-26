#!/usr/bin/env python3

BOLD, RESET = '\033[1m', '\033[0m'

def print_banner(name='Nameless', version='00.00.00', author='unknown'):
    banner = """
**************** 
 ***************
   ****      ***    ***      *** *********** ****     *********  ***
     ****    ***     ***    ***      ***    ******    ***     ** ***
      ****   ***      ***  ***       ***   ***  ***   *********  ***
     ****    ***       ******        ***  *** ** ***  ***        ***
   ****      ***        ****         *** ***      *** ***        ***
 ***************          {}author: {}{} | {}version: {}{}
****************
""".format(BOLD, RESET, author, BOLD, RESET, version)
    print(banner)

