---
title: How (not) to provide secure access to a secret I
description:
date: 2020-12-20 20:10
tags: [reversing, hardware, crypto, binary-exploitaiton]
layout: post
---

Hello reader! May I ask if you own a GPU from NVIDIA? Or a Nintendo Switch? Maybe an NVIDIA Shield? All of these
devices have something in common: a weird piece of hardware that is called the NVIDIA Falcon.

It's a processor for general-purpose logic controlling that is used across many different devices for different purposes.
Normally, this would be no target of interest if it did not have a hardware-based implementation of the Advanced Encryption
Standard for cryptographic operations. This functionality is used to restrict access of certain system resources
and registers to cryptographically signed microcode for better security in protecting hardware from being
misprogrammed, enforcement of DRM (HDCP, Widevine) and even to implement a Secure Boot environment on the Nintendo Switch.
Latter is what is going to be the topic of the blog as it is the most advanced example of how secure firmware on the
Falcon could look like.

NVIDIA describes this cryptosystem as ["Providing secure access to a secret"](https://patents.google.com/patent/US8245307)
so let's take a closer look at how the security of these devices was defeated and what could've been done better to
secure them properly. In this first part of multiple articles, let's look at how the previously mentioned TSEC firmware
motivated Falcon hacking and how it was defeated.

## Homebrew on the Horizon

In the earlier days of Nintendo Switch hacking, the entrypoints to homebrew were rather rudimentary and only provided
a very limited amount of system resources to be used by the developers of these unsigned and unauthorized pieces of
code, referred to as homebrew. A custom firmware environment that could patch, bypass or entirely escalate certain
components of the Horizon system became mandatory to give users and developers more freedom in using the system to its
fullest potential. But for this to work, there was a need to be able to derive all keys used by Horizon from custom code so
everything could play together nicely and work the intended way while allowing us to use the system resources we need
for advanced homebrew.

The entire cryptosystem back then devolved around two console-unique keys which were used in combination with some other keys
from the internal storage to derive static keys for everything else: The Secure Boot Key (SBK) set by the bootrom and the TSEC
key, generated from the KFUSE private key. By using the hardware-based Falcon cryptography, latter key was derived at boot stage
by an authenticated firmware we could not tamper with and was passed back to the Boot CPU through the SOR1 registers the Boot
processor and Falcon processor share mutual access to.

Considering you could run this TSEC firmware even from a userland context and just copy back the key it sets, the interest
in messing with a poorly documented processor, its hardware authentication mechanisms and even the code written for the
foreign instruction set architecture was not very high and the TSEC was ignored for most part.

## Recovering Trust

After a timeskip, now with [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere) being able to coldboot from a flaw in
the Tegra X1 bootrom before any Horizon code actually starts, hackers had control over the entire system with nothing Nintendo
could do about this....other than drastically gearing up the security from this one piece of hardware that was previously avoided -
You guessed it, the [TSEC](https://switchbrew.org/wiki/TSEC). We still depended on the TSEC key and another newly introduced
key, the TSEC Root key, so we couldn't leave any parts of Nintendo's new TSEC firmware away and had to run it as-is. We
couldn't sign our own firmware either or modify it as it would not generate the same keys then. HOVI (the team of NVIDIA and Nintendo
engineers working on the TSEC stuff) was well aware of this fact and used the TSEC's capabilities to, as soon as we ran the
firmware, rewrite the exception vectors of the Boot processor, decrypt and calculate a MAC over Nintendo's bootloader from more
unknown hardware secrets, and lastly set the program counter straight to the bootloader which redirects execution back into trusted
and verified code.

A mature attempt by Nintendo to secure their system despite having a bootrom vulnerability leading to arbitrary code execution.
No excuses anymore, the TSEC needed to be defeated. So let's approach this firmware and take a closer look at
its different stages and how they are used to implement a Secure Boot environment as one of the state of the art firmwares which
use the TSEC to its fullest capabilities to secure the boot chain.

## A First Look at the Firmware

For the purpose of this article, we'll be analyzing the 8.1.0 firmware as the previous versions had drastically more attack
surface to fault injection and were bypassable by other means, a memory virtualization trick to make the TSEC think it handed
control back to Nintendo's code while just yielding execution back to pages we control and giving us the key, which does not
deal with TSEC security at all.

### Anatomy of the Blob

The TSEC's firmware is loaded into the code memory (IMEM) by the first bootloader. Said IMEM uses primitive virtual memory/paging
in 0x100 byte pages tracked by a reverse page table. When uploading code, it must always be aligned to 0x100 bytes and if a blob
doesn't fit whole pages, it must be padded with zeroes. Code can tag certain pages as 'secure' which causes the hardware to
calculate and verify a MAC when landing on such 'secure' pages.

When taking a look at the firmware in a hex editor, we can recognize the patterns of page alignment and identify most of the
individual stages. But the firmware does not only consist of code, but also uses one page starting from physical address 0x300 to
get the sizes of all blobs, some key derivation seeds and the cryptographic hashes for all signed stages.

![TSEC Firmware in 010 Editor](/assets/img/how-not-to-provide-secure-access-to-a-secret/hex_key_data.png){:class="img-responsive"}

### Extracting the Stages

Knowing the sizes of the individual stages from the key data blob, we can build a small script to split everything up.

```py
    (
        boot_size,
        keygenldr_size,
        keygen_size,
        securebootldr_size,
        secureboot_size
    ) = unpack(
         '16s16s16s16s16s16s16sIIIII124x',
         package1_blob[key_blob_data_start:key_blob_data_end]
    )[7:]

    blob_pos = 0
    blob_pos = dump_blob(tsec_dir / 'boot.bin', package1_blob, blob_pos, boot_size)
    blob_pos = dump_blob(tsec_dir / 'key_table.bin', package1_blob, blob_pos, 0x100)
    blob_pos = dump_blob(tsec_dir / 'keygenldr.bin', package1_blob, blob_pos, keygenldr_size)
    blob_pos = dump_blob(tsec_dir / 'keygen.bin', package1_blob, blob_pos, keygen_size)
    blob_pos = dump_blob(tsec_dir / 'secureboot.bin', package1_blob, blob_pos, secureboot_size)
    blob_pos = dump_blob(tsec_dir / 'securebootldr.bin', package1_blob, blob_pos, securebootldr_size)
```

Back in the days where nobody cared about this, the firmware consisted of Boot -> KeygenLdr -> Keygen. The 6.2.0 update
extended it to Boot -> SecureBootLdr -> KeygenLdr -> Keygen -> SecureBoot, but the layout of the original firmware
is preserved in the sense that KeygenLdr and Keygen are placed at the same position in memory. We'll get back to that later
but for now we can start to reverse all the firmwares in order. Back in the good old days (actually also quite some time
after the Falcon was already defeated), this was done by hand with [envydis](https://github.com/envytools/envytools), the
only disassembler we had back then. But with the efforts put into [ghidra_falcon](https://github.com/Thog/ghidra_falcon)
since then, the game has changed a bit.

## The Entrypoint: Boot

![Boot main method](/assets/img/how-not-to-provide-secure-access-to-a-secret/boot_main.png){:class="img-responsive"}

After loading the Boot stage into Ghidra, we notice some `crt0` code which sets the stack pointer to the end of the Falcon DMEM
(a space for stack and local variables, completely separated from code memory IMEM), then jumps to `main`.

The `main` function itself is fairly unspectacular too: We have a `memcpy` which copies the first 0x84 bytes of the key data
blob from IMEM to DMEM. Comparing this with what we've previously seen in the hex editor, it sums up the sizes of Boot, KeygenLdr,
Keygen and SecureBoot plus 0x100 bytes for the key data page itself to calculate the entrypoint of the next stage, SecureBootLdr,
and then jumps to it.

This is certainly not what we probably expected from the first stage of a secure firmware, but with all other firmwares
hardcoding the key data to the same address (0x300), NVIDIA decided it is easier to move the previous implementation of Boot
along with all the new additions and future room for more code to a newly introduced stage, SecureBootLdr, which does not break
compatibility with KeygenLdr and Keygen which previously existed already. That being said, we can move on to analyze SecureBootLdr
which hopefully contains more information for us.

## The Real Entrypoint: SecureBootLdr

At address 0x3000, the start of SecureBootLdr, we're sent to `securebootldr_main` which does quite a lot of stuff. So let's
break it down and follow all stages it sends us to in order. This will help in understanding the design of the firmware
and give us the details we require to understand all of the code.

![First chunk of securebootldr_main](/assets/img/how-not-to-provide-secure-access-to-a-secret/securebootldr_keygen.png){:class="img-responsive"}

The method starts by copying the key data blob from address 0x300 in IMEM to a buffer in DMEM, we already know that behavior
from Boot, and uses the information about KeygenLdr's size to copy the blob to DMEM. But we can also go the other way round
and copy data from DMEM to IMEM. This may seem like an unnecessary detour knowing that KeygenLdr was located in IMEM previously
but this is in fact a necessary step. It lets the programmer control the virtual address from which a stage should be executed,
as branches mostly depend on fixed addresses, without destroying compatibility on future updates but also allows tagging
re-uploaded pages as 'secure'. And this is exactly the case here.

Then it loads the virtual start address and the size of KeygenLdr into the `$sec` SPR, transfers the auth hash from the
key data into crypto register 6 via the DMA override functionality for crypto registers (`cxset`) and jumps to KeygenLdr passing
a pointer to the key data copy and some other arguments we cannot identify yet.

And this is where things are starting to get interesting: We're about to leave No Secure mode and transist to Heavy Secure mode
execution under `KeygenLdr` by letting the hardware calculate a MAC over the code region specified in `$sec` and comparing it
to the auth hash we provided.

## From Falcon to Failcon: KeygenLdr

Now in Heavy Secure mode, we're running code that is officially signed and validated by NVIDIA with no possibility for us to manipulate
it. The hardware also makes sure that execution starts at 0x300 so we can't just jump to random places within the secure pages.

KeygenLdr starts by clearing interrupt bits, finishing pending DMA transfers, clearing all crypto registers and validating stack
boundaries so it can't exceed the size of DMEM or drop below 0x800 to avoid the risk of a stack smash. This mitigates all
influences we could have on the code from No Secure mode execution before calling `load_and_execute_keygen`. This function on the other
hand calculates an AES-CMAC over the Boot blob and then decrypts, authenticates and executes Keygen. So what's actually happening
there in detail?

### maconstack

The first couple of issues to talk about here begin with the CMAC check over the Boot code.

![AES-CMAC in KeygenLdr](/assets/img/how-not-to-provide-secure-access-to-a-secret/keygenldr_cmac.png){:class="img-responsive"}

As you remember, Boot was that thing that would directly jump into SecureBootLdr which then launches KeygenLdr. This means that
we cannot touch the Boot code but could still use our own SecureBootLdr to bring up this blob from an environment we control.
The reason why this was still preserved from times where Boot was responsible for bringing up KeygenLdr is compatibility with the
key derivation algorithms. If you change one byte in KeygenLdr, it would produce other keys and would not be able to decrypt Keygen
which derives the TSEC key.

...But this wouldn't actually be a problem! The auth signature of **Keygen** would still stay the same even if different keys were used
from KeygenLdr to decrypt it. The correct approach would have been to verify both, Boot AND SecureBootLdr. If Boot was verified
only, users could build a custom SecureBootLdr and vice versa. So in the end, either way, users could hack together an environment that
brings up KeygenLdr while still passing that MAC check.

But there is an even bigger problem going on here - maconstack, initially discovered by [@hexkyz](https://twitter.com/hexkyz). The
`signature_key` buffer where the final MAC is copied to will be preserved throughout the entire function and its contents are going to be
preserved in memory even after returning from it which makes it possible to abuse KeygenLdr as an oracle to generate auth hashes for
arbitrary code and read them back via a DMEM dump after the firmware halted the processor. As a result, we can run the TSEC firmware
with a Boot blob controlled by us.

This flaw is symbolic of a feature that is essential for this kind of cryptosystem and is yet still missing: memcpy for crypto registers.
There are cases where it is perfectly reasonable to spill keys into DMEM, but this kind of mistake could be simply avoided if there was
a possibility to validate the CMAC while not having to move it out of the crypto registers at the same time. If KeygenLdr had no other flaws,
this would be sufficient to secure the MAC check. Nonetheless, the emphasis is on 'had no other flaws', because we're not done yet.

### The Border between NS and HS

When the MAC check succeeds, either by abusing maconstack or leaving the Boot stage as-is, `load_and_execute_keygen` will continue to
decrypt the Keygen stage in the next step as the `is_keygen_dec` argument that was passed from SecureBootLdr is set to `0`.

![Decrypting the Keygen stage](/assets/img/how-not-to-provide-secure-access-to-a-secret/keygenldr_keygen_dec.png){:class="img-responsive"}

We know the pattern of re-mapping code pages as 'secure' already, but this time the encrypted Keygen blob in memory is first being decrypted
with AES-CBC. Later, the blob gets cleared out from DMEM as we should obviously not be able to obtain its plaintext. The attentive reader
might have noticed this already, but the sizes of each memcpy operation are directly taken out of the completely unverified key data table.
This wouldn't be a problem if they consistently did their stack guards everywhere data is being copied, like for Keygen here.

But already at the very beginning of this method, where the Boot blob is copied for CMAC:

```c
// Copy the Boot blob to address 0 in DMEM
memcpy_i2d(0,0,*(uint *)(key_buffer + 0x70));
```

the size is taken out of the key blob directly, leaving us with a possibility to craft a custom Boot blob that is capable of smashing the
stack with the only restriction that the stack pointer must stay above 0x800 when entering KeygenLdr! As this prolly screams to be exploited,
a lot of individuals have discovered this flaw independently back then. Virtual memory makes it possible to preserve the same memory mappings,
so we exploited this flaw by setting the stack pointer to 0xA00 in SecureBootLdr before jumping to KeygenLdr. And when `memcpy_i2d` places its return address at 0x998, we can have the Boot blob place the jump addresses for a ROP chain starting from there.

```
.size 0x998
.section #rop_payload 0x998

// mov $r10 0x1
// ret
.b32 0x5B8

// lbra #derive_keygenldr_key
.b32 0x647

...
```

This ROP chain can be made up into calling `derive_keygenldr_key` with the respective arguments to generate both `CODE_SIG_01` and
`CODE_ENC_01` keys with an ACL value of 0x13. These keys, similarly to the CMAC, are readable from an insecure context and can be
spilled from `$c4` to DMEM by calling `crypto_load`. But we should first read up on how these keys are even derived.

### Key Derivation

![Key derivation under KeygenLdr](/assets/img/how-not-to-provide-secure-access-to-a-secret/keygenldr_key_derivation.png){:class="img-responsive"}

The function generates a seed into a buffer of 16 bytes. This buffer gets loaded into `$c0` and will be encrypted with csecret 0x26.
This csecret has an Access Control List (ACL) value of 0x10, meaning that we cannot read it out of a crypto register. The resulting
ciphertext of that hash will obtain the same ACL value so that we cannot obtain this KEK either. But the final step, `Encrypt_Sig`
or `csigenc`, encrypts the auth hash of KeygenLdr with that previously crafted KEK. Additionally, key expansion can be done if the
key is needed for a dec operation, but let's focus on that signature encryption mechanism here.

After `Encrypt_Sig`, the register containing the final key has an ACL value of 0x13, meaning that it is considered insecure and can
be read. The deal with this is that after encrypting the signature with a KEK derived from hardware secrets, there's no possibility
to restore the original KEK anymore from it. Other firmwares which would attempt to generate the same key, by deriving the same KEK
and providing the known auth hash manually for an `Encrypt` Operation would yet again end up with an ACL 0x10 value and couldn't read
this key.

This is the Falcon's mechanism to ensure that the cryptosystem cannot corrupt itself as in firmwares being able to derive keys they
shouldn't have access to. But although the hardware does not treat the key as confidential anymore after `Encrypt_Sig`, this does not
mean that the key can safely be exposed to the outside! It is still a confidential secret of the individual firmware that derived it,
just not for the independent cryptosystem as a whole anymore. This makes the setting of ACL 0x13 a double-edged sword for vulnerable
firmwares as an attacker with ROP could always spill such keys to a visible place, like we did.

### Implementing the Crypto Functionality

From previous reversing of KeygenLdr, we know that a method `do_crypto` is responsible for actual cryptographic operations with various
arguments. It utilizes a key in `$c4` that was previously derived by `derive_keygenldr_key`. Now that we have the keys in question, we can
model this functionality in Python to have a more convenient way of messing with the system from our PC.

```py
from binascii import unhexlify
from Crypto.Cipher import AES

CODE_SIG_01 = unhexlify("<redacted>")
CODE_ENC_01 = unhexlify("<redacted>")

def sxor(x, y):
    return bytearray(a ^ b for a, b in zip(x, y))

def hswap(value):
    return (
        ((value & 0xFF) << 0x8 | (value & 0xFF00) >> 8) << 0x10
        | ((value & 0xFF0000) >> 0x10) << 0x8
        | value >> 0x18
    )

def generate_signature_key(size):
    buffer = bytearray(AES.block_size)
    buffer[0xC:] = hswap(size).to_bytes(4, "little")

    mode = 0x4  # AES-ECB encrypt
    return do_crypto(buffer, CODE_SIG_01, mode)

def do_crypto(source, key, mode, iv = None):
    if not iv:
        iv = bytearray(AES.block_size)
    
    if mode == 0x0:  # AES-CBC decrypt
        return AES.new(key, AES.MODE_CBC, iv).decrypt(source)
    elif mode == 0x1:  # AES-CBC encrypt
        return AES.new(key, AES.MODE_CBC, iv).encrypt(source)
    elif mode == 0x2:  # AES-CMAC
        aes = AES.new(key, AES.MODE_ECB)
        cmac = iv
        for i in range(0, len(source), AES.block_size):
            cmac = aes.encrypt(sxor(source[i:i + AES.block_size]), cmac)
        return cmac
    elif mode == 0x3:  # AES-ECB decrypt
        return AES.new(key, AES.MODE_ECB).decrypt(source)
    elif mode == 0x4:  # AES-ECB encrypt
        return AES.new(key, AES.MODE_ECB).encrypt(source)
    else:
        raise ValueError("unsupported mode given")

def sign_boot(boot):
    signature_key = generate_signature_key(len(boot))

    mode = 0x2  # AES-CMAC
    return do_crypto(boot, CODE_SIG_01, mode, signature_key)

def decrypt_keygen(keygen, iv = None):
    mode = 0x0  # AES-CBC decrypt
    return do_crypto(keygen, CODE_ENC_01, mode, iv)
```

With that, we can sign our own Boot blob and also decrypt Keygen!

### Executing Keygen

![Keygen execution](/assets/img/how-not-to-provide-secure-access-to-a-secret/keygenldr_keygen.png){:class="img-responsive"}

Like KeygenLdr, Keygen is executed with custom arguments. In this case, the first argument is a pointer into the key data blob.
Depending on our key version argument, it selects one of three possible seeds from the key data blob. With version `1`, passed by
SecureBootLdr, the `HOVI_EKS_01` seed is chosen.

After returning from Keygen, there are more cleanup routines to prevent data leaks to No Secure mode. These cleanup routines at the
beginning and at the end of a Heavy Secure mode payload are critical even though we have ROP because it prevents us from inserting
or exfiltrating data from the insecure world outside and drastically lowers the possibilities in how effective the ROP chain can be
used. We'll see what this means when moving on to Keygen.

## A Story of Trust and Despair: Keygen

With all of the handwork we previously did, we can decrypt the Keygen stage with `decrypt_keygen` from the script we wrote and start
to analyze the resulting plaintext blob.

Upon jumping to `keygen_main`, the following code will execute:

![The Keygen main method](/assets/img/how-not-to-provide-secure-access-to-a-secret/keygen_main.png){:class="img-responsive"}

Again some interrupt handling, DMA configuration and final cleanup to avoid leaking state, but by far not as many security
measurements as there were in KeygenLdr. It calls `generate_tsec_key` which derives and outputs the real TSEC key to SOR1 MMIOs.
Let's take a closer look at how this works.

### The Keygen in Keygen

When the `generate_tsec_key` method executes, it loads the seed buffer argument into `$c2`, then runs a keygen algorithm based on
the key version and finally transfers the key back into DMEM which then gets transferred to the SOR1 registers over DMA.

The algorithm for `HOVI_COMMON_01`:

![HOVI_COMMON_01 keygen](/assets/img/how-not-to-provide-secure-access-to-a-secret/hovi_common_key.png){:class="img-responsive"}

The algorithm for `HOVI_EKS_01`:

![HOVI_EKS_01 keygen](/assets/img/how-not-to-provide-secure-access-to-a-secret/hovi_eks_key.png){:class="img-responsive"}

Having access to the key derivation algorithm for both seeds, this also explains their names. While the first algorithm uses
exclusively csecret 0x00, which is equal across all TSEC engines, to derive its key, the latter algorithm additionally uses
csecret 0x3f, the console-unique KFUSE private key.

Keygen, by design, writes the final key in either case to a place where we have access to. And from hax and investigation in KeygenLdr,
we have its plaintext and know how to launch it correctly. So there's no need to hack it, is it?

### Investigating into Heavy Secure Authentication: The BootROM

While it is correct that there's no need to hack Keygen if we just wanted the keys it produces. We just have to run it and read
the result back, it's as easy as that. But compared to KeygenLdr, there's something else that becomes interesting here. When diffing
`keygen_main` against `keygenldr_main`, one immediately notices how Keygen does not clear any crypto registers before executing
`generate_tsec_key`. So with some possibility to hack it, we could dump the values of crypto registers after authentication into
Heavy Secure mode. This could be a starting point to reverse-engineer the algorithm behind the hardware check.

To understand why this is important, one must know that the Falcon has a secure BootROM that serves as an exception handler to
events NVIDIA refers to as "invalid instruction". The name doesn't really have anything to do with what it is actually about,
but who needs logic when you're a hardware engineer, right? And while this piece of code we don't have access to does the auth,
we can spy on it via some MMIOs that reveal the crypto command the Secure Co-Processor is executing. The algorithm can be
reconstructed as:

```armasm
csecret $c3 0x1
ckeyreg $c3
cenc $c3 $c7
ckeyreg $c3
cenc $c4 $c5
csigcmp $c4 $c6
```

A constant in `$c7`, in official microcode always set to zeroes due to xor, is encrypted with csecret 0x01 into `$c3`. Then something
else in `$c5` gets encrypted with that previously derived signing key and this is being compared to our auth hash in `$c6`. But `$c5`
is still a mystery which needs some possibility to dump crypto registers directly after authentication - that's where Keygen becomes
relevant.

### Big Boy ROP under Keygen

ROP under Keygen is the new strategy...but how? After reading it up and down, it has seemingly no attack surface*, such as trivial memcpys
with controllable size*. But as they forgot an important check about collision between `$sp` and the seed buffer, we can provide a
custom seed from an environment we control, let it run through one of the keygen algorithms, and hope that the ciphertext is a valid
jump address for smashing the stack. Crazy, you think? Yes, I though so too, but here we go.

When we were doing this, we got our hands on a vulnerable HDCP binary unrelated to the TSEC firmware which allowed us to dump exclusively
`$c2` and also without clearing the crypto registers after auth. But since `$c0` to `$c2` are not used during auth and thus are no relevant
targets to us, we still had to get back to Keygen. But at least we could use this HDCP binary to dump plaintext csecret 0x00. Since this
csecret 0x00 is treated as an insecure key by hardware, it has an ACL value of 0x13 that lets us spill it from crypto register to DMEM.

And with that key, we had the `HOVI_COMMON_01` algorithm in our hands. The other one relies on the KFUSE private key which is protected by
ACL 0x10, the highest level of confidentiality, so there's no chance for us to get this one. But at least we could now brute-force a pair
of plaintext and ciphertext where the plaintext encodes the return address of `generate_tsec_key` as the first word and the ciphertext has
the address of the first ROP gadget stored in the low 16 bits of the first word:

```py
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CSECRET_00 = unhexlify("<redacted>")
KEYGEN_SIG = unhexlify("892A36228D49E0484D480CB0ACDA0234")
GENERATE_TSEC_KEY_RET = 0x929
FIRST_GADGET = 0x94D

def hovi_common_01_enc(seed):
    kek = AES.new(CSECRET_00, AES.MODE_ECB).encrypt(seed)  # Encrypt our seed with the csecret
    return AES.new(kek, AES.MODE_ECB).encrypt(KEYGEN_SIG)  # Encrypt the signature with the new KEK

# If you're wondering, $sp and $pc only implement enough bits necessary to cover
# the IMEM and the DMEM of a Falcon engine. For the TSEC, that means 16 bits.
# All higher bits get truncated which simplifies the bruteforce by a lot.
u16 = lambda c: int.from_bytes(c[0:4], "little") & 0xFFFF

def prepare_plaintext():
    block = bytearray(get_random_bytes(AES.block_size))
    # Put the return address of generate_tsec_key as the first word.
    block[0:4] = GENERATE_TSEC_KEY_RET.to_bytes(4, "little")
    return block

while True:
    plaintext = prepare_plaintext()
    ciphertext = hovi_common_01_enc(plaintext)

    if u16(ciphertext) == FIRST_GADGET:
        print(f"Plaintext:  {hexlify(plaintext)}\nCiphertext: {hexlify(ciphertext)}\n")
```

With that, we can build a ROP chain under Keygen that is capable of dumping arbitrary crypto registers to our liking.
With that possibility, one could dump intermediary values of the Heavy Secure authentication check to reimplement it
via trial and error as the input parameters (code virtual address, the number of pages and the code itself) are known.
This is yet again influenced by the fact that Keygen does not clear the crypto registers when being executed: Since
Keygen does not do a `csecret $cX 0x1`, we have to do this from No Secure mode control in advance and make our ROP
chain work with the register containing the key.

### Faking the Signatures

But not only does the previous work with enough commitment reveal that `$c5` contains a Davies Meyer MAC calculated over
the code pages. It also reveals that the signing key which is used to encrypt this MAC depends on a constant value in `$c7`
which can be controlled by us. And again `csigenc` is our best friend here. By building another ROP chain on top of
Keygen, we can trick it into encrypting its signature (that we know) with csecret 0x01 and spill the result into DMEM.

So when we load in the signature of Keygen into `$c7`, regardless of the code, it will calculate the same """signing key"""
as what `csigenc` just handed over to us - effectively allowing us to sign arbitrary code into Heavy Secure mode!

## Conclusions

As fun as it was, the journey for now ends here.

To recapitulate everything that happened: We reversed a proprietary firmware with poor documentation and discussed a few
vulnerabilities leading to the disclosure of confidential secrets restricted to the firmware due to missing validation of
input data from outside in a high-security domain. Multiple stages relying on each other with poor validation of the
execution environment leaded to the possibility to reverse the hardware authentication algorithm and exploit a vulnerability
which could only be exploited under the circumstance of having control over `$sp` and the seed bufer pointer. And lastly, design
flaws throughout the system are conflicting with each other and contribute their share to several exploits.

Throughout this article, we fully examined Boot, SecureBootLdr, KeygenLdr and Keygen. In the next part, the SecureBoot
stage and its encrypted Falcon OS image will be discussed and analyzed. See you then!

## Credits

Credit where credit is due:

* [@Thog](https://twitter.com/ThogDev) for being my research partner and her patience in tirelessly listening to my
late-night rants about how crappy NVIDIA is
* [@SciresM](https://twitter.com/SciresM) and [@hexkyz](https://twitter.com/hexkyz) for answering many of my stupid
questions about certain crypto functionality
