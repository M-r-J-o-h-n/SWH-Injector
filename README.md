# Introduction

This inejctor uses 

1. physical memory,
2. two signed dll that contains rwx section
3. SetWindowedHookEx
4. Copy On Write

to manual map your dll into protected game by anti cheat.



The idea is well explained below image.

![Idea](C:\Users\Hunter\Documents\GitHub\SWH-Injector\1.PNG)



# How it works

We need two signed dlls that contains rwx section.

One for our manual mapper code, and One for a dll to be injected.



The injector loads a signed dll with rwx section which is "ShellContainer.dll".

You can always replace it to whatever you favor. 

But you have to find a dll that doesn't do any write operation on rwx section, Because it will trigger COW. Then the physical memory space of rwx section wouldn't be shared between different processes.

It then loads a process hacker's driver to access physical memory so that we can write on rwx section without triggering COW.

Using the driver, it writes manual mapper code directly on physical memory of rwx section.

Next, by using SetWindowedHookEx we inject the same dll into target process.

Then our manual mapper code will inject a signed dll that contains rwx which is not required to above restriction. it then maps target dll on rwx section.

When the injection completes, the injector unhook it. 

Then the ShellContainer.dll is automatically unloaded.



# FeedBack

Code review is welcome!

Especially the part of determining physical memory size of PhysicalMemory.cpp.



# credits 

<unknowncheats.me>
namazso - rwx meme
Tormund - his idea of injector
harakirinox - Physmem