# Calvin Walter Heintzelman
# ECE 404
# Homework 3
# Python 3.7.2

import os
import sys

print("Please enter a small digit: ")
number = input()

while(number.isdigit() is False or int(number) < 1):
    print("Error! Please only input a single small positive integer!")
    number = input()

if(int(number) >= 50):
    print('Warning! The input is not that small. Are you sure you want to input an integer that is 50 or greater?')
    print('Please anser "y" or "n"')
    continue_running = input()
    while(not(continue_running == 'y' or continue_running == 'n')):
        print('Error! Please enter "y" or "n"')
        continue_running = input()
    if continue_running == 'n':
        print('Please enter a number less than 50')
        number = input()
        while(number.isdigit() is False or  int(number) >= 50 or int(number) < 1):
            print('Error! Please only input a positive single integer that is less than 50')
            number = input()

number = int(number)
test_prime = 2
is_prime = True

if number == 1:
    is_prime = False

while(test_prime <= number/2):
    possible_factor = number % test_prime
    if possible_factor == 0:
        is_prime = False
        break
    test_prime += 1

if is_prime is True:
    print('field')
else:
    print('ring')