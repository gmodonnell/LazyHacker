"""
Main interface file. Imports everything else and lets
the end user pick and choose what they want to do with
the tool.
"""

from datetime import datetime
from colorama import Fore, Style
import osintcalls
import auditcalls

# Logo Function because ASCII is 1337
def logo():
    Y = Fore.YELLOW
    B = Fore.BLUE
    RED = Fore.RED
    U = Fore.CYAN
    RC = Style.RESET_ALL

    print(f"""

        {Y}:dddd,.
         .oooOOoo:.
             .ooOOOoo..
                ..loxkO'{B}:{Y}odc
                    ...{B}::{Y}OOOOOkl;.
                        {B}'{Y}0OOOOOOOOOOOd{B}..{Y}
                         .ok000OOOOkc{B}::{Y}OOdc'
                            .coxxxOO{B}::{Y}OOOOOOOklc:c,
                                .'.{B}::{Y}OOOOOOOOOOOOOdl{B}..{Y}
                                   {B}::{Y}OOOOOOOOOOOOOO{B}::{Y}oxxo;.
                                    {B}:{Y}okOOOOOOOOOOl{B}:::{Y}OOOOOOOOxc,.
                                        :dkkOOOOO{B}:::{Y}OOOOOOOOOOk{B}odocc;{Y}.
                                           ,;co{B}:::{Y}OOOOOOOOOOo{B}:oOOl{Y}coddxo:.
                                               {B}:{Y}OOOOOOOOOx,{B}oOk:{Y}c0Oolc:;,lO;
              {RED}Recon Enthusiast{Y}                 :OOOOOOOOx.{B}kOo{Y}'00{U}cokkkxo{Y};' do
                 v2.0 - for {U}Maltek Solutions{Y}      'ddkxOO.{B}dOx{Y}.Xk{U}ckkkkkkkx{Y}:, 0
                                                     .,,c {B}OO'{Y}dN{U};kkkkkkkkk{Y} : k
                                                        . {B}lk.{Y}kN{U},kkkkkkkk{Y},;. 0
                                                          {B} ..{Y};N{U}cokkkkko{Y},,..O
                                                            {B} .{Y}cXl{U},:c:'{Y}...ll
                                                                ckkdlooo

{RC}""")

def menu():
    print("=" * 70)
    print("1. SLAM IT (Everything)")
    print("2. Look Around (Scanning)")
    print("3. Ask the Locals (OSINT)")
    print("4. Spend Money (API Services)")
    print("5. Assess the Situation (Automated Auditing)")
    choice = input("What Now? (Int): ")
    match choice:
        case "1":
            slamit()
        case "2":
            scanning()
        case "3":
            osint()
        case "4":
            apis()
        case "5":
            audits()
        case _:
            print("Menu input accepts integers 1-5 only...")


def slamit():
    # Will need to be optimized for the most efficient
    # Order of task execution so things don't sit on
    # pause all day because I forgot to put in an API key.
    pass

def scanning():
    pass

def osint():
    domain = input(f"{datetime.now()} Type domain: ")
    pass

def apis():
    domain = input(f"{datetime.now()} Type domain: ")
    osintcalls.darkowlQuery(domain)
    pass

def audits():
    pass

if __name__ == "__main__":
    logo()
    menu()