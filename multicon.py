# GNU GENERAL PUBLIC LICENSE
#                        Version 2, June 1991
#
#  Copyright (C) 1989, 1991 Free Software Foundation, Inc., <http://fsf.org/>
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#  Everyone is permitted to copy and distribute verbatim copies
#  of this license document, but changing it is not allowed.
#
#  Please refer to LICENSE file contained within this repository for
#  full license information.
#
# =====================
#  == MultiCon v0.02  	==
# =====================
#
# Author:     Daniele Bastianello
# Version:    0.02
# Description: This program's purpose it to provide the user the ability to decode/encode strings to and from
#           various formats (such as shellcode, % or # delimited ASCII, ...). The utility is intended for SOC/NOC
#           environments to help with packet breakdowns and what ever "Other" purposes the user can think of.
#
#              This tool is intended to be multi-platform eventually but has only been tested under Ubuntu 14.04, 
#           14.10, 15.04 and Windows 8.1. The program is still under development thus problems may occur, these 
#           will eventually be corrected as my schedule allows.
#           
#           This program requires tkinter to function if under debian based system you need to install by issuing: 
#           sudo apt-get install python3-tk
#
#           If under windows installing python3 which can be found at python.org which comes with the tkinter api.


import platform
from tkinter import *
from tkinter import ttk


def mcon_lin():
    input_label.place(relx=0.1, rely=0.05, anchor=CENTER)
    input_text.place(relx=0.42, rely=0.28, anchor=CENTER)
    output_label.place(relx=0.105, rely=0.54, anchor=CENTER)
    output_text.place(relx=0.42, rely=0.7675, anchor=CENTER)

    delimiter_label.place(relx=0.9, rely=0.4, anchor=CENTER)
    delimiter_menu.place(relx=0.9, rely=0.44, anchor=CENTER)

    open_button.place(relx=0.9, rely=0.35, anchor=CENTER)
    decode_button.place(relx=0.9, rely=0.5, anchor=CENTER)
    encode_button.place(relx=0.9, rely=0.55, anchor=CENTER)
    save_button.place(relx=0.9, rely=0.6, anchor=CENTER)


def mcon_win():
    input_label.place(relx=0.05, rely=0.035, anchor=CENTER)
    input_text.place(relx=0.44, rely=0.28, anchor=CENTER)
    output_label.place(relx=0.05, rely=0.52, anchor=CENTER)
    output_text.place(relx=0.44, rely=0.76, anchor=CENTER)

    delimiter_label.place(relx=0.94, rely=0.4, anchor=CENTER)
    delimiter_menu.place(relx=0.94, rely=0.44, anchor=CENTER)

    open_button.place(relx=0.94, rely=0.35, anchor=CENTER)
    decode_button.place(relx=0.94, rely=0.5, anchor=CENTER)
    encode_button.place(relx=0.94, rely=0.55, anchor=CENTER)
    save_button.place(relx=0.94, rely=0.6, anchor=CENTER)


# This definition deals with creating a gui file_picker using tkinter
def file_picker():
    from tkinter.filedialog import askopenfilename
    return askopenfilename()


# This def deals with inserting the text into the main_paine window
def load_data(file_name):
    if file_name is not "":
        with open(file_name, 'r') as file_contents:
            data = file_contents.read()
        input_text.delete(1.0, END)
        input_text.insert(INSERT, data)


# This def deals with saving the file and appends .mcon to any filename thus reducing overwriting
# original file.
def save_file():
    from tkinter.filedialog import asksaveasfilename

    new_name = asksaveasfilename() + ".mcon"
    with open(new_name, 'w') as outFile:
        outFile.write(output_text.get(1.0, END))


# This definition has as input either, manually entered/pasted text in the input text box or the file
# contents provided from the file_picker definition.
#
# The encoder currently only supports ASCII hex and UTF-8 and will eventually evolve to support UTF-16.
# It also only deals with none, \x, % and # delimiters to detect the ASCII within the strings provided.
def decode(data):
    output_text.delete(1.0, END)
    check = delimiter_select.get()[0]
    # below is needed since I do not want tmp_data to be a global variable
    tmp_data = ""

    if check is "\x5c":
        for i in data:
            if i is "\x5c":
                tmp_data = tmp_data + "0"
            else:
                tmp_data = tmp_data + i
        data = tmp_data
        search_string = "0x([A-Fa-f0-9]{2})"
    else:
        search_string = delimiter_select.get() + "([A-Fa-f0-9]{2})"

    decoded_text = re.sub(search_string, lambda mc: chr(int(mc.groups()[0], 16)), data)

    if decoded_text is not None:
        output_text.insert(INSERT, decoded_text)


# This definition has as input either, manually entered/pasted text in the input text box or the file
# contents provided from the file_picker definition.
#
# The encoder currently only supports ASCII hex and UTF-8 and will eventually evolve to support UTF-16.
# It also only deals with none, \x, % and # delimiters to detect the ASCII within the strings provided.
def encode():
    data = input_text.get(1.0, END)
    size = len(data) - 1
    output_text.delete(1.0, END)
    encode_text = None

    if delimiter_select.get() == "none":
        for i in range(0, size):
            if i == 0:
                encode_text = encode_text + format(ord(data[i]), "x")
            encode_text = encode_text + " " + format(ord(data[i]), "x")
    else:
        for i in range(0, size):
            encode_text = encode_text + delimiter_select.get() + format(ord(data[i]), "x")

    if encode_text is not None:
        output_text.insert(INSERT, encode_text)
    else:
        output_text.insert(INSERT, "\t\tDid you enter anything?\n\t\t         . .\n\t\t          v")

# Below are the buttons function calls when clicked
def onclick_open():
    open_button.configure(command=load_data(file_picker()))


def onclick_decode():
    decode_button.configure(command=decode(input_text.get(1.0, END)))


def onclick_encode():
    encode_button.configure(command=encode())


def onclick_save():
    save_button.configure(command=save_file())


# Creating the main program window and all widgets.
root = Tk()
# root.iconbitmap('@./mcico.xbm')
root.resizable(0, 0)
root.title("MultiCon")

main_paine = ttk.Frame(root, width=800, height=560)
main_paine.pack()

input_label = ttk.Label(main_paine, text="Input Text")
input_text = Text(main_paine, width=85, height=15)
output_label = ttk.Label(main_paine, text="Output Text")
output_text = Text(main_paine, width=85, height=15)

delimiter_label = ttk.Label(main_paine, text="Delimiter")
delimiter_select = StringVar(main_paine)
delimiter_menu = ttk.OptionMenu(main_paine, delimiter_select, "none", "none", "%", "#", "\\x")

open_button = ttk.Button(main_paine, text="Open", command=onclick_open)
decode_button = ttk.Button(main_paine, text="Decode", command=onclick_decode)
encode_button = ttk.Button(main_paine, text="Encode", command=onclick_encode)
save_button = ttk.Button(main_paine, text="Save", command=onclick_save)

ttk.Button()

if platform.system() == "Linux":
    mcon_lin()
elif platform.system() == "Windows":
    mcon_win()
else:
    print("Operating System is not supported(yet!). Your OS is detected as: " + platform.system())

root.mainloop()
