---
title: "Reversing Unity Games - Case Study: Among Us"
description: Using Among Us as an example, I'm going to present an approach to reversing Unity games
             with an emphasis on networking and practical code analysis.
date: 2020-11-18 14:29
tags: [reversing, game-hacking]
layout: post
---

Even before the idea of this blog even arose, I've been asked about reversing Among Us and examining
its information as more and more people started to get interested in it. I decided this is a great
idea since I personally got interested in game hacking a whole lot recently and found this to be a
great example to showcase some Unity game reversing.

Without any prior information on Among Us and the underlying engine in detail, let's dive right in
and see where this takes us and whether we can gain enough information to reimplement the network
protocol and the online features of the game.

### Getting Started

As a rule per thumb: Whenever you plan to reverse a game, make sure to actually play it! This probably
sounds obvious, but seriously think about the in-game structures you encounter, what could be possible
handled client-side, what could be taken care of by the server, and how the game is generally put
together.

Even Among Us, while being a rather simplistic example, is complex enough to give you a real struggle
in understanding its inner relations without knowing any gameplay. Take your time to play and
think about these things from the perspective of a developer or hacker rather than a player.

### Reversing the Game Binary

An initial look into the installation directory of the game (in my case, a copy for messing around)
reveals that the game was built in the popular game engine [Unity](https://unity.com/de). Unity
provides rich scripting for games in C# through Mono, so my first though was "this is going to be
a piece of cake".

![File system structure](/unity-reversing-case-study-among-us/filesystem.png)

But turns out, the Among Us developers had other plans for us! They made use of a Unity feature called
[IL2CPP](https://docs.unity3d.com/Manual/IL2CPP.html) which compiles the C# Assembly logic of the game's
scripting into native C++ code. The `il2cpp_data` directory in `Among Us_Data` gives hints about this.
Of course, we are not intimidated by the fact that we're going to reverse machine code generated from
C++ and start right away to explore this binary.

With no prior experience with IL2CPP, I started to inspect `Among Us.exe` in [Ghidra](https://ghidra-sre.org/)
which is just an entrypoint to the Unity runtime by calling `UnityMain` from the `UnityPlayer.dll` library.
So I did some more research about IL2CPP on the interwebs and learned that `GameAssembly.dll` is what contains
the actual game logic.

![WinMain function of the Among Us.exe](/unity-reversing-case-study-among-us/winmain.png)

### Reversing GameAssembly.dll

At the same time, I came across [Il2CppInspector](https://github.com/djkaty/Il2CppInspector)
which is capable of restoring class, function and type information for the `GameAssembly.dll` C++ logic,
which is a MASSIVE time saver over trying to do this by hand.

![Il2CppInspector Usage](/unity-reversing-case-study-among-us/il2cppinspector.png)

We can feed it the `GameAssembly.dll` along with the `Among Us_Data/il2cpp_data/Metadata/global-metadata.dat`
file and it exports the resources we need to get proper analysis of `GameAssembly.dll` inside Ghidra.

After loading it in, we click "No" when being prompted to auto-analyze the code. Instead, we parse the
previously exported header file and execute the Python script to get the analysis we desire. For me,
this took a very long time to complete, so be patient, get yourself some tea and relax while Ghidra
labels everything.

When the process is done, the script produced all the relevant symbols for us. However, they are all
mangled into output like `?dllmain_dispatch@@YAHQAUHINSTANCE__@@KQAX@Z`. Fortunately, Ghidra ships with
a certain `DemangleAllScript.java` which makes our lives a lot easier. It demangles all the signatures
into readable output and from there we can start to examine the list of functions of this clusterfuck for
useful stuff related to the network protocol.

After some digging around and inspecting cross-references to functions with interesting names, we learn
that most of the networking is done by a class called `InnerNetClient`. With a closer look at all the
methods that seem like they could do some networking, e.g. `InnerNetClient#KickUser`, we'll notice the
usage of a `MessageWriter` instance to outline a message definition.

![MessageWriter use for serializing a Kick packet](/unity-reversing-case-study-among-us/messagewriter.png)

Something that immediately hits the eye is the encapsulation of `MessageWriter#StartMessage`, followed by
packet data serialization, terminated by `MessageWriter#EndMessage`. After that, the `MessageWriter` object
is being passed to `InnerNetClient#FLAJOMCGOMK`, which presumably sends the message to the server and ultimately
`MessageWriter#Recycle` is used to free the memory allocated for the message buffer.

*In unrelated news, I have several theories about how the name of the send method originated: Crack consumption, the cat running over the keyboard, a rampage, or all of these.*

Examining these functions reveals that `MessageWriter#StartMessage` pushes the start position of the internal
message buffer onto a stack structure stored by the instance. This is necessary because `MessageWriter#EndMessage`
will need the start position to calculate the total length of the message which gets encoded in the first two bytes
of the packet. Accordingly, `StartMessage` reserves those bytes in position so no packet data get written to it.
Following up the packet length, a single byte known as the `typeFlag` gets encoded. This identifies the type of packet
that we're looking at (and thus gives hints about how to parse the follow-up data).

This can be further visualized through a Wireshark scan, which reveals further details (such as the use of UDP
for communication).

![Among Us Wireshark Scan](/unity-reversing-case-study-among-us/wireshark.png)

We see the sequence `22 00` which turns into `0x22` bytes analogously to `Data (34 bytes)`. This is correct!
The following type flag is `0`...

![InnerNetClient HostGame](/unity-reversing-case-study-among-us/hostgame.png)

...which matches the implementation of `InnerNetClient#HostGame`!! This serves us as instructions on how to
identify and learn every game packet we don't know about yet.

*...Again such funky names...*

### Understanding the Protocol

Now we need to get our hands dirty and actually look at how `MessageWriter`'s API serializes supplied value
types into packets. Its design comes very close to a Rust [`Cursor`](https://doc.rust-lang.org/std/io/struct.Cursor.html),
in case you're familiar with the language. And if you aren't, read the link anyway because it's a
good explanation.

#### Serializing Integers

![MessageWriter Write Halfword](/unity-reversing-case-study-among-us/write_halfword.png)

We have different methods for serializing 8-bit, 16-bit and 32-bit signed and unsigned integers. All of the
formats (except byte, obviously) are written in little-endian byteorder to the internal buffer maintained by
the `MessageWriter` instance.

#### Serializing Floating-Point Numbers

![MessageWriter Write Single](/unity-reversing-case-study-among-us/write_single.png)

Floating-point numbers are represented through the [`Single`](https://docs.microsoft.com/de-de/dotnet/api/system.single?view=net-5.0)
structure on the C# side. In contrast to the integer approach, these are written as bytes in big-endian order.

#### Serializing Strings

In case of a string, the serialization is two-fold. For one part, a string gets lowered down into a byte array
through `UTF8Encoding.UTF8.GetBytes` and the length of said array gets written to the packet using the
[packing algorithm](#the-packing-algorithm). And for the other part, the byte array representing the string gets
written.

For raw byte arrays, not related to strings, one can choose whether to pack the length of it too or just write
the raw data.

#### The Packing Algorithm

![MessageWriter WritePacked](/unity-reversing-case-study-among-us/packing.png)

For certain purposes in Among Us, e.g. packing Player IDs, a packing algorithm is applied to 32-bit integers.

It works by doing a `while (true)` loop that ends when the value to write is zero. In every round, the low
8 bits of the current value get OR'd with `0x80`. If the result of that is smaller than `0x80`, the unmodified
low 8 bits are used. This is then being written to the buffer like a single byte. And finally, the value to
write gets shifted to right by 7 bits and the algorithm repeats. The purpose of all this is to store a number
within a 32-bit boundary in as few bytes as possible.

#### Conclusions

By reversing `MessageWriter` and doing a rudimentary Wireshark scan, we learned the structure of packets, the
serialization of types, and the communication protocol, UDP. By reversing `InnerNetClient`, we learn the concrete
layout of different types of packets and their purpose. And so we got a precise overview of the game client's workings
and a previously fully unknown packet protocol with no knowledge of the game in advance and minimal knowledge
of Unity internals. This provides enough information to implement the client protocol. By analyzing the callbacks
for server packets, one can learn about server-side messages and how a client is supposed to handle them.

Parallel to that, there's a `InnerNetServer` class which contains networking logic for a server. Diving into this
will reveal the information an open source game server reimplementation would need. A funny and educational project
idea, left as an exercise to the reader. 😉
