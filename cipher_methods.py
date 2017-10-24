#!/usr/bin/python

import math     #sqrt
import sys      #exit
import getpass  #getpass
import base64   #b64encode
import os       #path.getsize
import argparse	#ArgumentParser
import gc       #dis/enable

#Hunter DeMeyer
#task.py
#4/4/2017
#v0.6
# This program obfuscates and encrypts an inut string using a four square cipher.
# a four square cipher uses four blocks of characters, with some of the
# characters in two diagonal blocks padded and mangled by passphrases. The message is
# split into strings with a length of 2. This string is used as 2 of four corners
# on a rectangle superimposed over a combination of the four blocks of characters.
# The other two corners of the superimposed rectangle are the new characters in the message.
# https://learncryptography.com/classical-encryption/four-square-cipher

# TODO
# add public key support
#
# limit length of input file
#
# add a progress bar or real time output
#
# use this to encrypt messages sent between 2 computers
#
# test the strength of this algorithm. This involves writing a program to crack the cipher.
#   I have a reference implementation written to crack english from the standard lowercase
#   alphabet with 'i' omitted to make it square. I would have to modify this algorithim to
#   analyze base64 encoded text
#
# show the hash of the en/deciphered data

#this has all the characters in base64 which should be called base65 because of the = padding
#but the square in a four square cipher doesnt actually have to be a square so now its a
#rectangle. I wrote a method below that will split this into a 2d array that is most square like
#for any length array in case this changes. I chose to use a 2d list instead of a regular list because
#it illustrates the execution of the cipher better and makes my code easier to understand. I could have
#just used math to compute the location of the corresponding character in a 1d list but that introduces
#complications and python should be "complex but not complicated".
quad =  [
    "a","b","c","d","e","f","g","h",
    "i","j","k","l","m","n","o","p",
    "q","r","s","t","u","v","w","x",
    "y","z","A","B","C","D","E","F",
    "G","H","I","J","K","L","M","N",
    "O","P","Q","R","S","T","U","V",
    "W","X","Y","Z","1","2","3","4",
    "5","6","7","8","9","0","+","/",
    "="
]

parser = argparse.ArgumentParser(description=" Symmetrical De/enciphering of inputted data. Secure enough for everyday use in the home.")
parser.add_argument("-d", "--decipher", help="Decipher the input", action="store_true")
parser.add_argument("-i", "--input", help="Specify an input file", type=str)
parser.add_argument("-o", "--output", help="Specify an output file", type=str)
parser.add_argument("--show-blocks", action="store_true", help="Show the character blocks used for enciphering.(Experts Only)")
parser.add_argument("-v","--verbose", action="store_true", help="Enable display of progress. Enable automatically for large inputs")

args = parser.parse_args()

#add the password to the beginning of the quad and split into 2d list
def add_passphrase(passwd, quad):
    n = len(quad)
    r_quad = []
    quad = list(passwd) + quad
    i = 0
    while len(r_quad) < n:
        if quad[i] not in r_quad:
            r_quad += quad[i]
        i += 1
    r_quad = r_quad[:n]
    return split_2d(r_quad, get_dimensions(len(r_quad)))

#split the list into a 2d list
def split_2d(q, n):
    r_quad = []
    for i in range(int(len(q) / n)):
        l = q[:n]
        r_quad.append(l)
        q = q[n:]
    return r_quad

#find the dimensions that are most square-like
def get_dimensions(n):
    factors = []
    i = n-1
    while i > 1:
        if n % i == 0:
            if i in factors:
                break
            else:
                factors.append(i)
        i -= 1
    return factors[-1]

#split input string into pairs and return a list
def digraph_split(str):
    #Disabling garbage collection helps slightly with the time it takes to encode larger inputs
    #I mean *very* slightly but I don't have a better way of doing it. By providing an index
    #instead of appending I also save some time. The root problem is that a python list is, at
    #heart, an arraylist. It doubles in size every time it becomes full. Preallocating seems
    #not to help much either but I beleive a combination of these two methods has some worthwhile
    #impact on time
    gc.disable()
    digraph_list = int(len(str)/2)*["aa"]
    i = 0
    j = 2
    k = 0
    if args.verbose:
        while j <= len(str):
            digraph_list[k] = (str[i:j])
            i += 2
            j += 2
            k += 1
            print("\rSplitting...", end="")
            progress = k*2/len(str)*100
            print("{0:.3f}".format(progress), end="")
    else:
        while j <= len(str):
            digraph_list[k] = (str[i:j])
            i += 2
            j += 2
            k += 1
    #add a pad character to make even digraphs if necessary
    if len(digraph_list[-1]) == 1:
        digraph_list[-1] = digraph_list[-1][0] + " "
    gc.enable()
    if args.verbose:
        print("\rSplitting...Splitting done")
    return digraph_list

#get the corresponding characters from character square
#1  3
#2  4
def char_swap_encrypt(digraph, q1, q2, q3, q4):
    cipher_digraph = ""
    char1 = digraph[0]
    char2 = digraph[1]
    char1_loc = []
    char2_loc = []

    for row in range(0, len(q1)):
        for col in range(len(q1[row])):
            if q1[row][col] == char1:
                char1_loc = [row,col]
                break

    for row in range(0, len(q4)):
        for col in range(len(q4[row])):
            if q4[row][col] == char2:
                char2_loc = [row,col]
                break
    cipher_digraph += q2[char2_loc[0]][char1_loc[1]]
    cipher_digraph += q3[char1_loc[0]][char2_loc[1]]
    return cipher_digraph

#decrypt a digraph by fetching corresponding characters from the character square
def char_swap_decrypt(digraph, q1, q2, q3, q4):
    return char_swap_encrypt(digraph, q2, q1, q4, q3)

#call the previous methods to create the ciphertext
def four_square_encipher(plain, q1, q2, q3, q4):
    ciphertext = ""
    if args.verbose:
        for d in digraph_split(plain):
            ciphertext += char_swap_encrypt(d, q1, q2, q3, q4)
            print("\rEnciphering...", end="")
            progress = len(ciphertext)/len(plain)*100
            print("{0:.3f}".format(progress), end="")
        print("\rEnciphering...Enciphering done")
    else:
        for d in digraph_split(plain):
            ciphertext += char_swap_encrypt(d, q1, q2, q3, q4)

    return ciphertext

#decipher an enciphered string using previous methods
def four_square_decipher(cipher, q1, q2, q3, q4):
    plaintext = ""
    if args.verbose:
        for d in digraph_split(cipher):
            plaintext += char_swap_decrypt(d, q1, q2, q3, q4)
            print("\r", end="")
            print("\rDeciphering...", end="")
            progress = len(plaintext)/len(cipher)*100
            print("{0:.3f}".format(progress), end="")
        print("\rEnciphering...Deciphering done")
    else:
        for d in digraph_split(cipher):
            plaintext += char_swap_decrypt(d, q1, q2, q3, q4)
    return plaintext

#display the cipher
def display_squares(q1, q2, q3, q4):
    for row in range(0,len(q1)):
        for col in range(len(q1[row])):
            print(q1[row][col], end=' ')
        print('', end=' ')
        for col in range(len(q3[row])):
            print(q3[row][col], end=' ')
        print()
    print()
    for row in range(0,len(q2)):
        for col in range(len(q2[row])):
            print(q2[row][col], end=' ')
        print('', end=' ')
        for col in range(len(q4[row])):
            print(q4[row][col], end=' ')
        print()

#handle all of the problems associated with file opening in here
def open_file(path, mode):
    #if args.verbose:
        #print("Opening " + path + "...", end="")
    try:
        #warn about large files (100MB or more)
        if path == args.input and os.path.getsize(path) >= 100*1000000:
            choice = "n"
            choice = input("Warning: this file may take a long time. Continue?[y/N]: ")
            choice = choice.lower()
            if not choice == "y" and not choice == "n":
                sys.exit()
            else:
                if choice == "y":
                    args.verbose = True
                    f = open(path, mode)
                    return f
                else:
                    sys.exit()
        else:
            #if args.verbose:
                #print("done")
            return open(path, mode)
    except (PermissionError, FileNotFoundError, OSError) as e:
        #print("error")
        print(e)
        sys.exit()
