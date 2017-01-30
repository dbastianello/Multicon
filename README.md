Multicon
(De)obfuscation program was developed to help those who deal with packet analysis in network intrusion analysis environments

GNU GENERAL PUBLIC LICENSE Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc., <http://fsf.org/>
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

 Please refer to LICENSE file contained within this repository for
 full license information.

====================
== MultiCon v0.02 ==
====================

Author:     Daniele Bastianello
Version:    0.02
Description: This program's purpose it to provide the user the ability to decode/encode strings to and from various formats (such as shellcode, % or delimited ASCII, ...). The utility is intended for SOC/NOC environments to help with packet breakdowns and what ever "Other" purposes the user can think of.

This tool is intended to be multi-platform eventually but has only been tested under Ubuntu 14.04, 14.10, 15.04 and Windows 8.1. The program is still under development thus problems may occur, these will eventually be corrected as my schedule allows.
          
This program requires tkinter to function if under debian based system you need to install by issuing: 
	sudo apt-get install python3-tk

If under windows installing python3 which can be found at python.org which comes with the tkinter api.
