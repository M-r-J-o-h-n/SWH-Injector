# Introduction

This inejctor uses 

1. physical memory,
2. two signed dll that contains rwx section
3. SetWindowsHookEx
4. Copy On Write

to manual map your dll into protected game by anti cheat.



[Imgur](https://imgur.com/AJojXut)

This explains well the idea.

# How to use

Command line : SignedDll.dll TargetDll.dll TargetProcName.exe


Tested on windows 10 1803.

SEH is not supported!

# How it works

We need two signed dlls that contain rwx section.

One for our manual mapper code, and One for a dll to be injected.



The injector loads a signed dll with rwx section which is "ShellContainer.dll".

You can always replace it to whatever you favor. 

But you have to find a dll that doesn't do any write operation on rwx section on initialization routine. Because it will trigger COW. Then the physical memory space of rwx section wouldn't be shared between different processes.

It then loads a process hacker's driver to access physical memory so that we can write on rwx section without triggering COW. 

Using the driver, it writes manual mapper code directly on physical memory of rwx section.

Next, by using SetWindowsHookEx The injector injects the same dll into target process.

Then our manual mapper code will loadlibrary a signed dll that contains rwx that the restriction above is not required. It then maps target dll on rwx section of the dll.

When the injection completes, the injector unhook it. 

Then the ShellContainer.dll is automatically unloaded.



# Warning

The code might not be ready to compile and run.

I made this injector on january this year.

If you use this injector to cheat in BE or EAC games, i recommend you to modify it.

At least change the way you access physical memory, and use other signed dlls.



# FeedBack

Code review is welcome!

Especially the part of determining physical memory size of PhysicalMemory.cpp.



# Credits 

> namazso - rwx meme
>
> can1357 - perfect injector source
>
> Tormund - his idea of injector
>
> harakirinox - Physmem
>
> 

