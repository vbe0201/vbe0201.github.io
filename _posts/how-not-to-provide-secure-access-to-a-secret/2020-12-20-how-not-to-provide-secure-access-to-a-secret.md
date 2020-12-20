---
title: How (not) to provide secure access to a secret I
description:
date: 2020-12-20 20:10
tags: [reversing, hardware, binary-exploitaiton]
layout: post
---

Hello reader! May I ask if you own a GPU from NVIDIA? Or a Nintendo Switch? Maybe an NVIDIA Shield? All of these
devices have something in common: a weird piece of hardware that is called the NVIDIA Falcon.

It's a general-purpose logic controller that is used across many different devices for different purposes. Normally,
this would be no target of interest if it did not have a hardware-based implementation of the Advanced Encryption
Standard for cryptographic operations. This functionality is used to restrict access of certain system resources
and registers to cryptographically signed microcode for better security in protecting hardware from being
misprogrammed, enforcement of DRM (HDCP, Widevine) and even Secure Boot.

NVIDIA describes this cryptosystem as ["Providing secure access to a secret"](https://patents.google.com/patent/US8245307)
so let's take a closer look at how the security of these devices was defeated and what could've been done better to
secure it properly. In this first part of multiple articles, let's look at how the Falcon became a target of hacking
efforts and how seemingly secure firmware is rolled on the platform along with all of its mistakes.

### Credits

* [@Thog](https://twitter.com/ThogDev) for being my research partner and her patience in tirelessly listening to my
late-night rants about how crappy NVIDIA as a company is
* [@SciresM](https://twitter.com/SciresM) and [@hexkyz](https://twitter.com/hexkyz) for answering many of my stupid
questions about certain crypto functionality
