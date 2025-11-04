---
title: "Breaking Bad Crypto Padlocks"
date: 2023-01-23T16:57:09+01:00
tags: [reversing, crypto]
draft: false
---

Some time around 2020/21, I began to build a server implementation for a certain game after some
prior work on GitHub helped kickstart the efforts. Soon enough, more people with aligned interests
were gathered and we bounced information on various technical aspects of said game.

Eventually we had most of the obscure details worked out...except for their network transport
encryption. And if you know *anything* about crypto in video games you rightly suspect bad things
ahead.

## Procrastinating the Task

Upon discussing it, we realized nobody actually looked into it in full detail. Someone built
a tool capable of dumping plaintexts by hooking the game's crypto functions and grabbing their
inputs and outputs, but that was about it.

We observed that the patch server, unlike the game servers, still communicates in plaintext. So we
tracked down a difference in *Session Offer*/*Accept* packet structures and quickly learned that
the server gets to decide whether it wants the client to encrypt the traffic or not.

Being the server author, this puts me in a very comfortable position. With trivial effort I was
able to circumvent the encryption and never had to bother with it again.

## Tackling the Key Exchange

Around the same time, an independent group of researchers reached out to me for unrelated reasons.
One of them later began to dive into the transport crypto out of personal curiosity and wrote their
findings down [in their own blog post](https://cedwards.xyz/foray-into-reverse-engineering/).

We learned that ciphertexts of the public keys, along with symmetric keys and IVs for decryption
are stored as one big blob in the client binary - presumably to limit our ability to search for
magic ASN.1 structure bytes.

The author has since built [`pubkey-extract`](https://github.com/cedws/pubkey-extract), which is
capable of extracting the RSA public keys from the binary and even injecting controlled key pairs.

The baseline is:

- Server sends *Session Offer* which selects one of the embedded public keys and confirms their
  validity through an attached signature

- Client sends *Session Accept* storing randomly generated AES key and nonce, encrypted with the
  selected public key

- Subsequent communication is encrypted and authenticated with AES-GCM using the exchanged key
  and nonce

From that point we still have plenty of work to do so let's get our hands dirty.

### Message structures

From Connor's work, we know the function where all the magic is happening. With more digging, we
can identify routines for binary data parsing, which allow recovering the structure of the signed
payload in *Session Offer* fairly quickly:

| Offset | Type       | Description                        |
|--------|------------|------------------------------------|
| 0xE    | uint32     | Length prefix for the following    |
| 0x12   | uint8      | A set of bit flags                 |
| 0x13   | uint8      | The selected key slot              |
| 0x14   | uint8      | The key xor mask for deobfuscation |
| 0x15   | uint8      | Challenge length in bytes          |
| 0x16   | uint8[]    | Serialized challenge data          |
| _      | uint32     | An echo value to send back as-is   |
| _      | uint8[256] | RSA signature over this blob       |

The same function then proceeds to build a response payload for *Session Accept*. We can
reconstruct it as follows:

| Offset | Type       | Description                        |
|--------|------------|------------------------------------|
| 0x10   | uint32     | Length prefix for the following    |
| 0x14   | uint8      | A set of bit flags                 |
| 0x15   | uint8      | Magic value 0x8? Maybe bitflags?   |
| 0x16   | uint8[]    | Serialized challenge response      |
| _      | uint32     | The echo value from Session Offer  |
| _      | int32      | The current time as UNIX timestamp |
| _      | uint8[16]  | 128-bit AES key for encryption     |
| _      | uint8[16]  | 128-bit GCM nonce                  |

> NOTE: Only the portion starting from 0x15 is RSA-encrypted.

> NOTE(2): Don't get me started on those bloody 32-bit timestamps.

## Challenges, or: Nightmare Fuel

Ok, you've read this and most of it seems self-explanatory. But what's the deal with these
ominous challenges?

Let's take a look at the handler function to find out. It is given the input buffer of
challenge data (`source`) and an output buffer for the resulting answer (`dest`).

![AnswerChallenge, part 1](/img/padlocks/fnv_decomp.png)

We are first reading two `u16`s (merged into one `u32` here, but equivalent results) values
which encode an *offset* into the static public key buffer and the *length* of subsequent bytes
to hash with [FNV-1a](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#FNV-1a_hash).

> NOTE: `pubkey-extract`, which was mentioned before, extracts the key buffer in question
  for that reason as well.

![AnswerChallenge, part 2](/img/padlocks/map_decomp.png)

The next part is where the real juice is happening. Most of this is an optimized access
pattern into a global map, so only the highlighted parts are relevant.

We're reading 1 byte (`challenge_type`) from our input buffer, then searching for a corresponding
entry in some map, and finally delegating to a virtual function call on the object we found.

At the time of writing, we only ever get the same challenge type `0xF1`:

![Challenge handler](/img/padlocks/f1_handler.png)

We see it reads three more `u32` values, does some calculations in another function and writes the
resulting `u32` value to the output.

Little did we know what would be awaiting us at that time.

![Go!](/img/padlocks/go.png)

### Concatvecs

This function would greet us with another virtual call which populates 3 byte vectors and then
performs concat operations into one big vector depending on the bits set in the first `u32`
argument.

![ConcatVecs](/img/padlocks/concatvecs.png)

But what is the data we're actually concatenating? A glance at the virtual call didn't reveal much.
Lots of obscure garbage and little motivation to detangle it. But one thing stood out - the
repeated use of the third `u32` argument in a certain function:

```py
def scramble_buffer(data: bytes, key: int) -> bytes:
    buf = bytearray()

    key_bytes = key.to_bytes(4, "little")
    step = (key & (1 <<  3)) >> (3  - 0)
         | (key & (1 <<  5)) >> (5  - 1)
         | (key & (1 <<  7)) >> (7  - 2)
         | (key & (1 << 14)) >> (14 - 3)
         | (key & (1 << 18)) >> (18 - 4)

    for b in data:
        if step != 0 and len(buf) != 0 and len(buf) % step == 0:
            buf.append(buf[-1])
        buf.append(key_bytes[len(buf) & 3] ^ b)

    return buf
```

Wait a sec. Run this function again chief. What? Almost the original `data` but not quite? Yeah,
this function is reversible. And although it took us a few nights of debugging to get it right
(we had not only implemented `unscramble_buffer` incorrectly but also `scramble_buffer`!), it
came together in the end:

```py
def unscramble_buffer(data: bytes, key: int) -> bytes:
    buf = bytearray()

    key_bytes = key.to_bytes(4, "little")
    step = (key & (1 <<  3)) >> (3  - 0)
         | (key & (1 <<  5)) >> (5  - 1)
         | (key & (1 <<  7)) >> (7  - 2)
         | (key & (1 << 14)) >> (14 - 3)
         | (key & (1 << 18)) >> (18 - 4)

    i = 0
    while i < len(data):
        if step != 0 and len(buf) != 0 and i % step == 0:
            i += 1
        buf.append(key_bytes[i & 3] ^ data[i])
        i += 1

    return buf
```

Running `unscramble_buffer` on the output vectors of the vcall...we just got different data
we *still* couldn't make much sense of!

### ClientSig

We did debug the same spot many times after that, always dumping the three populated vectors
and the scramble key and running `unscramble_buffer` on it - the output stayed consistent.

At this point we were a bit stuck. We would navigate the binary for `scramble_buffer` occurences
to see if maybe there's an easier way to approach this than having to reverse all the logic for
filling these vectors. :face_vomiting:

And the most promising thing we eventually stumbled across was the use of this function in a
handler routine for the `-CS` CLI flag. It uses an embedded public key to validate a
base64-encoded argument to the flag, then runs the obscure logic we've seen before, and
finally encrypts it before writing it to a file called `ClientSig.bin`.

We notice two things: this function uses a [512-bit RSA public key](https://en.wikipedia.org/wiki/RSA_numbers#RSA-155)
and it implements the check for the argument incorrectly - any 64 base64-encoded bytes will pass.

The first approach was to [inject a custom public key](https://gist.github.com/vbe0201/d9399b17408999c70eab9747d80b39f5)
for being able to decrypt the output. That worked semi-well - we were able to identify two of the
three vectors from earlier in it, but one segment changed completely.

We were eventually able to map them out as "where's waldo" (mostly the same repeated data with very
slight changes every now and then), offsets and code bytes from these offsets; kinda what you would
expect from a "ClientSig".

A researcher eventually figured out that the waldo buffer was module hashes and that the renamed
executable (`_Patched` suffix in the script) caused this deviation.

However, we didn't bother with that script anymore because it didn't take a day for us to factorize
the public key instead. So from then on, we used the actual private key to dump the ClientSig:

```cmd
.\Client.exe -CS fHL4SVK/N2rcUosoHzNwHV7L4am/xFMmhdwh3ETRepJPUwQ501SGKt9UUawD7OG1hDdC0/QfgYqOneI3L32HgA==
.\decrypt_client_sig.py ClientSig.bin
```

And indeed now the results matched! That being said, the script (with some modifications to not rename
the binary) will be viable for dumping the correct ClientSig as well.

> SHA256(private key) = D85D95250012B3B030E7D32B3EF54963C97712C870CB6B7B32DB8E089A1B9E2B

### Completing the puzzle

At that point, most of the heavy lifting was done.

![XOR ClientSig vector](/img/padlocks/xorvec.png)

We know the "scrambled" segments of ClientSig.bin are concatenated into a vector in varying order,
and now we're running another round of byte XOR on it with no apparent purpose.

![Integrity hash](/img/padlocks/hash.png)

And lastly, we can see the final hash which is configured by certain bitfields in the second
argument.

The actual byte processing function is selected from an array, including
[FNV-1a and FNV-1](https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function),
[Jenkins one_at_a_time](https://en.wikipedia.org/wiki/Jenkins_hash_function), and finally
[PJW hash](https://en.wikipedia.org/wiki/PJW_hash_function).

Now that we arrived at the other side of hell at last, we might call it a day here. To wrap it
up, here is a [reference implementation](https://gist.github.com/vbe0201/bd80a7ee805bb4341f1249fbae02b112)
of everything in its full glory.

## Symmetric encryption

This one actually messed up us for days, to the point where we had to gather for late-night
sessions of *Reversing Telephone*™.

![RE Telephone](/img/padlocks/stream.png)

I'll make the results of these endeavors short and simple because I'd like to discuss the
implications rather than the algorithm.

The game uses AES-GCM with a key and nonce exchanged in *Session Accept*. All the subsequent
traffic will be encrypted. After every `n` blocks worth of encrypted data, a new random nonce
and an authentication tag for the whole block of data processed so far will be attached.

I have decompiled and documented
[the client class which handles that](https://gist.github.com/vbe0201/171171fa8494383aa788f1af67b0338f)
for reference as well, if anyone wishes to implement this functionality.

Frame headers travel through the two-argument `Process`, whereas frame bodies are passed to
the four-argument `Process`.

The client authenticates `0x100` blocks of outgoing traffic at once, whereas the server
authenticates `0x1000` blocks.

### "AES-GCM is secure"

[AES-GCM sucks](https://soatok.blog/2020/05/13/why-aes-gcm-sucks/) for plenty of reasons, but
it is in fact a very solid choice to reach out for most of the time.

But let's address the elephant in the room - security is only granted as long as you're playing
by the rules of the construction. And that might not necessarily be something you are closely
familiar with when your decision finding process looks like this:

![StackOverflow to the rescue](/img/padlocks/stackoverflow.png)

#### GCM Streaming

AES-GCM uses AES-CTR for encryption underneath, so it shares the property of CTR that enables
decrypting data in a streaming fashion, effectively making it a stream cipher.

By XORing some of the keystream with the corresponding chunk of ciphertext, we can decrypt data
without needing the full message at once. However, the first and foremost rule of any AEAD is
that any data is **atomic waste** before the authentication tag was verified. Otherwise, this
will inevitably [lead to doom](https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html).

In fact, many libraries are tailored around this fact and don't grant access to plaintexts
before the authenticity and integrity of the message was verified. Some candidates like
[CryptoPP](https://github.com/weidai11/cryptopp) however behave just like an ordinary CTR cipher
on repeated calls to `ProcessData`... :cursing_face:

#### Reordering and Truncating

This is a general issue to address when chunking AEADs, which has been described in greater detail
[here](https://www.imperialviolet.org/2015/05/16/aeads.html).

An attacker can intercept traffic, replace the plaintext nonce after every `0x1000` byte chunk, and
transmit a different chunk along with its valid auth tag and a new nonce instead. Likewise, chunks
can be completely omitted this way.

TLS approaches this by keeping an internal count of messages and including the current count in
AAD for each message. The receiving end would then check if the expected counter value is given.

This is optimal for TCP-based protocols where delivery of every packet in order is guaranteed.

## Conclusions

That concludes the journey for today. We reverse-engineered the transport encryption that prevented
communication with the server except through the official client. Much love to all the folks who
helped make it happen.

At this point I'm not sure of the goal of all this - prevent packet injection? Obfuscate the
interface to make analysis harder? Protect against cheaters? Probably a bit of everything
yet nothing worked out.

Nonetheless, I personally hope the knowledge and code samples are put to good use. I'd love to see
more amazing projects of the likes of custom clients, datamining and analysis tools, further
reverse engineering efforts happen!

> Also: If you recognize `scramble_buffer` or some variant of it and know if it's any algorithm
  that was seen in the wild before, I'm dying to learn where. :monocle_face:
