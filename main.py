#!/usr/bin/python

from cipher_methods import *

plaintext = ""
ciphertext = ""
ciphertext64 = ""

def main():
    #check to make sure files specified can be opened
    temp = args.verbose
    args.verbose = False
    if not args.input == None:
        f = open_file(args.input, "r")
        f.close()
    if not args.output == None:
        f = open_file(args.output, "wb+")
        f.close()
    args.verbose = temp
    #ask for passwords use to encipher text
    pass1 = getpass.getpass("Enter passphrase 1: ")
    for char in pass1:
        if char not in quad:
            print("Illegal character in passphrase. Allowewd characters are [A-Z][a-z][0-9]+/")
            sys.exit()
    pass2 = getpass.getpass("Enter passphrase 2: ")
    for char in pass2:
        if char not in quad:
            print("Illegal character in passphrase. Allowewd characters are [A-Z][a-z][0-9]+/")
            sys.exit()

    #create the block of characters to use as the cipher
    top_left = split_2d(quad, get_dimensions(len(quad)))
    top_right = add_passphrase(pass1, quad)
    bottom_left = add_passphrase(pass2, quad)
    bottom_right = split_2d(quad, get_dimensions(len(quad)))

    #optionally show the blocks used to de/encipher
    if args.show_blocks:
        display_squares(top_left, bottom_left, top_right, bottom_right)

    #The remaining code handles cli options and decides what to do
    if not args.decipher:
        if args.input == None:
            plaintext = input("Enter text to encipher: ")
            plaintext = bytes(plaintext, "ascii")
            plaintext = (base64.b64encode(plaintext)).decode("ascii")
        else:
            in_file = open_file(args.input, "rb")
            plaintext = in_file.read()
            in_file.close()
            plaintext = (base64.b64encode(plaintext)).decode("ascii")
        if not args.output == None:
            out_file = open_file(args.output, "wb+")
        ciphertext = four_square_encipher(plaintext, top_left, bottom_left, top_right, bottom_right)
        if not args.output == None:
            out_file.write(bytes(ciphertext, "ascii"))
            out_file.close()
        else:
            print(ciphertext)
    else:
        if not args.input == None:
            f = open_file(args.input, "r")
            ciphertext = f.read()
            f.close()
        else:
            ciphertext = input("Enter text to decode: ")
        plaintext64 = four_square_decipher(ciphertext, top_left, bottom_left, top_right, bottom_right)
        #Things get slightly complex here because python's b64 de/encode expects a
        #binary string. Program doesn't know if original data was ascii or not
        if not args.output == None:
            out_file = open_file(args.output, "wb+")
        plaintext = base64.b64decode(bytes(plaintext64, "ascii"))
        if not args.output == None:
            out_file.write(plaintext)
            out_file.close()
        else:
            try:
                print(plaintext.decode("ascii"))
            except UnicodeDecodeError:
                print("Data may not have been ascii or passwords are wrong. Try agin with --output")

#I want to handle an int signal, not the best way but it works
try:
    main()
except KeyboardInterrupt:
    print("\nSignal caught, exiting cleanly...\n")
    sys.exit()
