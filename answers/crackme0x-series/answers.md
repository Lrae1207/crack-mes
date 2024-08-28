##crackme0x00.exe : using x32dbg "https://github.com/x64dbg/x64dbg"
execs/crackme0x00.exe
Password: "250382"

This one is found simply by one of two ways:
1. By searching for string references, one of which is a 6 digit code "250382"

2. These instructions:
```assembly
# Compares the user input that was previously collected to the password string
00401365 | lea eax,dword ptr ss:[ebp-18]
00401368 | mov dword ptr ss:[esp+4],crackme0x00.404027
00401370 | mov dword ptr ss:[esp],eax
00401373 | call <JMP.&strcmp>
00401378 | test eax,eax
________________________________
0040137A | je crackme0x00.40138A
```
if the above line succeeds:

```assembly
# prints "Password OK :)\n"
0040138A | mov dword ptr ss:[esp],crackme0x00.404041
00401391 | call <JMP.&printf>
```

otherwise:
```assembly
#prints "Invalid Password!\n"
0040137C | C70424 2E404000          | mov dword ptr ss:[esp],crackme0x00.40402E
00401383 | E8 A8190000              | call <JMP.&printf> 
00401388 | EB 0C                    | jmp crackme0x00.401396
```


##crackme0x01.exe : using x32dbg "https://github.com/x64dbg/x64dbg"
execs/crackme0x01.exe
Password: 0x149A -> "5274"

Similar to the previous one, this one can be cracked very simply. Unlike the previous, however, searching
for string references yields no results. However, searching in the code you can find:

```assembly
00401360 | call <JMP.&scanf>
00401365 | cmp dword ptr ss:[ebp-4],149A
0040136C | je crackme0x01.40137C
```

Basically, this checks the user input against a (clearly hexadecimal) value 0x149A which is converted to 
0d5274. If this comparison succeeds, "Password OK :)\n" is printed, and if not "Invalid Password!\n" is
printed.

##crackme0x02.exe : using ghidra "https://github.com/NationalSecurityAgency/ghidra"
execs/crackme0x02.exe

Password: 0x52b24 -> "338724"

Decompiling _main function yields:
```c
int __cdecl _main(int _Argc,char **_Argv,char **_Env) {
  size_t in_stack_ffffffe0;
  int userInput;
  
  __alloca(in_stack_ffffffe0);
  ___main();
  _printf("IOLI Crackme Level 0x02\n");
  _printf("Password: ");
  _scanf("%d",&local_8);
  if (local_8 == 0x52b24) {
    _printf("Password OK :)\n");
  } else {
    _printf("Invalid Password!\n");
  }
  return 0;
}
```

All that really matters are these lines:
```c
// user input is put into local_8
_scanf("%d",&local_8);
/ local_8 is what the password is checked against
if (local_8 == 0x52b24) {
  _printf("Password OK :)\n");
}
```

The password is equivalent to 0x52b24 or "338724"
