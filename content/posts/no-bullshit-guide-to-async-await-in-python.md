---
title: "No Bullshit Guide to async/await in Python"
date: 2025-11-04T15:28:31+01:00
tags: [python, async, programming, io]
draft: false
---

Greetings, reader! Welcome to your 35th tutorial on `async`/`await` so far
but I promise this one is worth it...at least if you're part of a specific
audience wanting to know how coroutines actually work under the hood.

Today we're going to build `minio`, a tiny `asyncio` clone from scratch for
teaching purposes.

## `async` and why we have it

You have probably written asynchronous code using the `async` and `await`
keywords before:

```py
import asyncio

async def serve(reader, writer):
    # Echo received data back to the client.
    data = await reader.read(100)  # (2)
    writer.write(data)
    await writer.drain()

    # Close the client connection when we're done.
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(serve, "127.0.0.1", 8888)
    async with server:
        await server.serve_forever()  # (1)

asyncio.run(main())
```

Seems easy enough, right? Some function calls require that you `await` them
and when you do that it has to be inside an `async def`. Apart from the extra
syntax, the program still feels very similar to a non-`async` one.

But it's called asynchronous for a reason! Our echo server above is perfectly
capable of serving many client connections at the same time, similar to a
multithreaded program. But here's the twist: This program is running on a
single thread.

To understand why that is, you have to realize most of the time in this
program is spent *waiting*:

- `(1)` waits for new clients to connect to the server. When they do, the
  handling is delegated to `serve`.

- `(2)` waits for a client to send some data, which is then echoed back.

Threads are a poor fit for this kind of concurrency. They're expensive to create,
the context switching is expensive, and most of the time they will just be lazing
around while they wait for clients. On top of that, we'd quickly hit some resource
limits if we created a thread per connection.

This is where coroutines shine. They are much lighter to create than a full-blown
thread and every `await` marks a potential suspension point. If a coroutine can't
make progress because it needs to wait, it can suspend and let something else run
in the meantime. The responsibility for timely reaching an `await` after a few
milliseconds of execution falls on the programmer.

{{< alert >}}
This is why you were taught to avoid blocking code in coroutines.
{{< /alert >}}

## Anatomy of a coroutine

With that out of the way, let's investigate a bit:

```py
>>> async def test():
...     print("I am a coroutine")
...
>>> c = test()
>>> c
<coroutine object test at 0x7ff3253c50c0>
```

A coroutine function produces a `coroutine` object when called? Who
would've guessed! But since we don't see the `print`, it is safe to
say that coroutines are lazy beasts. Now how do we run them?

It turns out that coroutines use the implementation of generators as
their backbone, which means they share a similar API:

```py
>>> c = test()
>>> c.send(None)
I am a coroutine
Traceback (most recent call last):
  File "<python-input-3>", line 1, in <module>
    c.send(None)
    ~~~~~~^^^^^^
StopIteration
```

There it is! We got our print and a `StopIteration` exception to indicate
that the coroutine is completed.

But that isn't all, we can also use the `throw` method from the generator
API to inject an exception at the current suspension point:

```py
>>> c = test()
>>> c.throw(ValueError("Oops"))
Traceback (most recent call last):
  File "<python-input-9>", line 1, in <module>
    c.throw(ValueError("Oops"))
    ~~~~~~~^^^^^^^^^^^^^^^^^^^^
  File "<python-input-0>", line 1, in test
    async def test():
ValueError: Oops
```

Now what happens if we try the last function from the generator trio?

```py
>>> c = test()
>>> c.close()
>>> c.send(None)
Traceback (most recent call last):
  File "<python-input-12>", line 1, in <module>
    c.send(None)
    ~~~~~~^^^^^^
RuntimeError: cannot reuse already awaited coroutine
```

Makes sense.

But now that we know how to run a coroutine, how do we make it suspend?
Well, we could try treating it like a generator again and simply yield.

```py
>>> async def test2():
...     yield "suspend?"
...
>>> c = test2()
>>> c.send(None)
Traceback (most recent call last):
  File "<python-input-28>", line 1, in <module>
    c.send(None)
    ^^^^^^
AttributeError: 'async_generator' object has no attribute 'send'. Did you mean: 'asend'?
```

...Not what I expected. Looks like you can't actually yield in a coroutine
because then it's not a `coroutine` anymore but an `async_generator`. :thinking:

Oh, I know. We could `await` something. But what exactly? We cannot pull in
`asyncio` because our goal is to make something of our own.

### Awaitables to the rescue

Luckily, coroutines have yet another important building block besides the actual
`coroutine` objects - *awaitables*.

An awaitable is anything that returns an iterable from its `__await__` method.
Yes, that applies to `coroutine` objects too:

```py
>>> for _ in test().__await__():
...     pass
...     
I am a coroutine
```

Let's experiment a bit:

```py
>>> class MyAwaitable:
...     def __await__(self):
...         yield
...
>>> async def test():
...     print("entered test()")
...     await MyAwaitable()
...     print("resumed test()")
...
>>> c = test()
>>> c.send(None)
entered test()
>>> c.send(None)
resumed test()
Traceback (most recent call last):
  File "<python-input-36>", line 1, in <module>
    c.send(None)
    ~~~~~~^^^^^^
StopIteration
```

And there it is! Notice how it takes two `send` calls to drive this coroutine
to completion? That's because the first call only executes the coroutine up
to the point where it suspends at `await` thanks to the `yield`.

But that is not all. There is another way to create awaitables that do not have
an `__await__` method - by decorating a generator function with `@types.coroutine`
which grants a regular generator object some superpowers from the Python gods:

```py
>>> import types
>>>
>>> @types.coroutine
... def a():
...     yield
...
>>> async def b():
...     await a()
...
>>> c = b()
>>> c.send(None)
>>> c.send(None)
Traceback (most recent call last):
  File "<python-input-50>", line 1, in <module>
    c.send(None)
    ~~~~~~^^^^^^
StopIteration
```

But the important takeaway here is: **Every await may be suspended by a yield at
some point down the line.**

## Baby's first run loop

With some coroutine theory out of the way, let's start laying our foundation.
We're going to implement some important cornerstones:

- A `Task` abstraction which represents coroutines that don't have a direct
  `await`er. This would be the coroutine passed to `minio.run()` but also the
  background tasks we're going to implement later.

- A mechanism for calling into the event loop without needing access to the
  runtime's internal state. We use the `_runtime_call` coroutine for this
  which suspends execution and passes a message of the form `(event, arg)`
  to the event loop.

- The event loop itself. It takes Tasks from a queue of Tasks ready to run,
  executes them until suspension, and processes the runtime call that was
  made.

  When any of the subsequent sections introduce a new type of runtime call,
  assume the handler method is registered to the `handlers` dictionary.

```py
import types
from collections import deque

class Task:
    def __init__(self, coro):
        self.coro = coro
        self.call_result = None
        self.result = None

@types.coroutine
def _runtime_call(event, value):
    call_result = yield (event, value)
    return call_result

class Runtime:
    def __init__(self):
        self.handlers = {}
        self.run_queue = deque()

    def run(self, coro):
        # Make a Task for the initial coroutine.
        root_task = Task(coro)

        # Run the event loop while there's still work left.
        self.run_queue.append(root_task)
        while self.run_queue:
            task = self.run_queue.popleft()
            try:
                event, arg = task.coro.send(task.call_result)

            except StopIteration as e:
                task.result = e.value

            except Exception as e:
                # Raise only exceptions from the main task.
                # Background tasks will die with a print.
                if task is root_task:
                    raise
                else:
                    print(e)

            else:
                handler = self.handlers[event]
                handler(task, arg)

        # Return the result of coro when we're done.
        return root_task.result

def run(coro):
    rt = Runtime()
    return rt.run(coro)
```

This is not doing a lot for now, but let's give it a shot:

```py
>>> import minio
>>>
>>> async def a():
...     raise ValueError("moo")
...
>>> async def b():
...     return 2
...
>>> minio.run(a())
Traceback (most recent call last):
  File "<python-input-4>", line 1, in <module>
    minio.run(a())
    ~~~~~~~~~^^^^^
  File "/home/vale/Coding/vbe0201.github.io/minio.py", line 53, in run
    return rt.run(coro)
           ~~~~~~^^^^^^
  File "/home/vale/Coding/vbe0201.github.io/minio.py", line 32, in run
    event, arg = task.coro.send(task.call_result)
                 ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^
  File "<python-input-2>", line 2, in a
    raise ValueError("moo")
ValueError: moo
>>> minio.run(b())
2
```

Seems good!

## Background tasks

At the start I said that the true power of coroutines is concurrency
without requiring multithreading. So that is our next hurdle. We need
the ability to start background tasks and we need to execute them.

First, we need a public `spawn` function which tells the runtime we
want to spawn a coroutine in the background.

```py
import inspect

async def spawn(coro):
    if not inspect.iscoroutine(coro):
        raise TypeError("coro must be a coroutine")
    return await _runtime_call("spawn", coro)
```

That's it! The runtime call will briefly suspend execution so that
the event loop gets to process the `"spawn"` event. We need a handler
for that in the `Runtime` class:

```py
    def handle_spawn(self, spawning_task, spawn_coro):
        spawn_task = Task(spawn_coro)

        # Append the task for the newly spawned coroutine
        # to the run queue so the event loop sees it.
        self.run_queue.append(spawn_task)

        # And since the spawning task is immediately ready
        # to make progress again, we put it to the front
        # of the run queue so it gets resumed immediately.
        spawning_task.call_result = None
        self.run_queue.appendleft(spawning_task)
```

Let's try it:

```py
>>> import minio
>>> async def bg(i):
...     print(f"I am background task {i}")
...
>>> async def main():
...     print("entering main()")
...     for i in range(10):
...         await minio.spawn(bg(i))
...     print("main() done")
...
>>> minio.run(main())
entering main()
main() done
I am background task 0
I am background task 1
I am background task 2
I am background task 3
I am background task 4
I am background task 5
I am background task 6
I am background task 7
I am background task 8
I am background task 9
```

Nice!

### Bonus: joining tasks

Now wouldn't it be useful if we could also wait for coroutines we spawned
to finish? Set your peepers on the changes we are making to support this:

```py
class Task:
    def __init__(self, coro):
        self.coro = coro
        self.data = None
        self.result = None
        # NEW: Set of Tasks waiting for this Task to finish.
        self.waiters = set()

# NEW:
class JoinHandle:
    def __init__(self, task):
        self.task = task

    def __await__(self):
        # "I want to wait until self.task finishes"
        yield from _runtime_call("join", self.task)
```

As for the event loop itself, we must support the new event type and
also inject a `JoinHandle` as the call result to `spawn()`:

```py
    def handle_spawn(self, spawning_task, spawn_coro):
        # ...
        spawning_task.call_result = JoinHandle(spawn_task)
        # ...

    def handle_join(self, waiting_task, join_task):
        # Register interest in being notified when join_task
        # completes. Until then, waiting_task will not be put
        # in the run queue again.
        join_task.waiters.add(waiting_task)

        waiting_task.call_result = None
```

Another subtle change is needed in the handling of `StopIteration`
so waiters get added to the run queue when a task completes:

```py
    except StopIteration as e:
        task.result = e.value
        self.run_queue.extend(task.waiters)  # !
```

Now let's test our changes:

```py
>>> import minio
>>>
>>> async def bg(num):
...     print(f"I am background task {num}")
...
>>> async def main():
...     print("entering main()")
...     for i in range(10):
...         jh = await minio.spawn(bg(i))
...         await jh
...     print("main() done")
...
>>> minio.run(main())
entering main()
I am background task 0
I am background task 1
I am background task 2
I am background task 3
I am background task 4
I am background task 5
I am background task 6
I am background task 7
I am background task 8
I am background task 9
main() done
```

See the difference? Now we don't have `main()` completing before the
background tasks anymore. Pretty cool, huh?

## Handling time

Let's add another feature that requires a Task to wait before it can
run again - timers. Specifically, we're going to add `minio.sleep()`
which lets us suspend a task for a given number of seconds before it
is woken again.

First, we're going to need a data structure to store timers in. Every
timer is a tuple `(deadline, task)` and we keep them in a min heap so
we always know the timer that expires next.

```py
from heapq import heappush, heappop

class TimerHeap:
    def __init__(self):
        self.timers = []

    def __len__(self):
        return len(self.timers)

    def add(self, task, secs):
        heappush(self.timers, (time.monotonic() + secs, task))

    def next_deadline(self):
        return self.timers[0][0] - time.monotonic()

    def get_elapsed(self):
        now = time.monotonic()
        while self and self.next_deadline() < now:
            _, task = heappop(self.timers)
            yield task
```

Now we need to integrate it into the `Runtime`. This is done by adding
an instance of `TimerHeap` to `__init__` and adapting the event loop
slightly:

```py
        # ...
        while self.run_queue or self.timers:
            # When no Tasks are left, pause the thread until the next
            # timer elapses and reap ready tasks into the run queue.
            if not self.run_queue:
                time.sleep(self.timers.next_deadline())
                for task in self.timers.get_elapsed():
                    self.run_queue.append(task)

            # Same as before from here...
            task = self.run_queue.popleft()
            # ...
```

Now the last step is a `sleep()` method which suspends the `Task`
until its timer elapses:

```py
async def sleep(delay):
    return await _runtime_call("sleep", delay)

# ...

    # ...And the corresponding event handler in Runtime
    def handle_sleep(self, task, delay):
        self.timers.add(task, delay)

        task.call_result = None
```

Let's test our change:

```py
>>> import minio
>>>
>>> async def main():
...     for _ in range(5):
...         await minio.sleep(2)
...         print("sleepy")
...         
>>> minio.run(main())
sleepy
sleepy
sleepy
sleepy
sleepy
```

Works like a charm. :partying_face:

## I/O support

Here comes the real juice. A coroutine runtime which doesn't handle
I/O is completely useless because I/O is the main source of all the
waiting we'll need to do.

### Nonblocking I/O and Selectors

Before we write some more code for `minio`, we must first discuss
how the pieces will fit together. We want to use networking code
from the builtin `socket` module because that is the low-level
building block from the operating system.

But wait, those APIs are blocking. And we dislike blocking code.
So for my next trick I'll just make them...not blocking. And I
mean it quite literally, we can call the `.setblocking(False)`
method and the world will be healed.

That is only half of the story though. What it does is it will cause
these APIs to return early when we'd have to wait for the operation
to complete. So are we just supposed to test the same operation over
and over again until eventually one succeeds?

Thankfully we are loved by the makers of our operating systems because
they bless us with APIs where we can register interest in a socket
becoming readable or writable and get notified when that is the case!
They carry funny names like `epoll` or `kqueue`.

And most importantly, we are also loved by the Python gods themselves
because they bless us with the builtin `selectors` module as a portable
wrapper for these APIs.

### Adding Runtime support

Now the first step is, again to make our `Runtime` play with it.

```py
# ...
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE

# ...

class Runtime:
    def __init__(self):
        # ...
        self.selector = DefaultSelector()
    
    def run(self, coro):
        # ...
        while self.run_queue or self.timers or self.selector.get_map():
            # When no Tasks are left, pause the thread while waiting
            # for I/O or timers. We use the timer closest to expiring
            # as the deadline for I/O waits.
            if not self.run_queue:
                to = self.timers.next_deadline() if self.timers else None
                for key, _ in self.selector.select(to):
                    self.run_queue.append(key.data)
                    self.selector.unregister(key.fileobj)

            # Check if we have any elapsed timers to reap.
            if self.timers:
                for task in self.timers.get_elapsed():
                    self.run_queue.append(task)

            # Same as before from here...
            task = self.run_queue.popleft()
```

Now that is quite something. Our `selector` maintains a mapping
of file objects to selector keys. So as long as that mapping is
non-empty, there will be `Task`s blocked on I/O (`selector.get_map()`).

If the run queue is empty, we need to wait for I/O or timers.
We do that with a `selector.select()` call using the timer closest
to expiring as a deadline.

If we do get completed I/O notifications, we can schedule these
tasks for execution and unregister our interest in notifications
(because now we can perform the operation without needing to wait
anymore).

Now the last missing piece is we need to register interest in
being notified when a file object becomes readable or writable.
We turn to none other than our runtime call system.

```py
async def _wait_readable(fileobj):
    return await _runtime_call("io", (EVENT_READ, fileobj))

async def _wait_writable(fileobj):
    return await _runtime_call("io", (EVENT_WRITE, fileobj))
```

And the appropriate handlers in `Runtime`:

```py
    def handle_io(self, task, data):
        # Register interest in the fileobj becoming readable
        # or writable. We attach the waiting Task to the map
        # so that we can associate every notification to the
        # Task it is meant for in the event loop.
        event, fileobj = data
        self.selector.register(fileobj, event, task)

        task.call_result = None
```

To say this is barebones is an understatement, but we will see
how this is applied to do useful things.

## Wrapping up

Last but not least, we want our I/O abstraction to do something.
What better way is there to wrap this journey up than to go back
to what it started with.

```py
import minio
import socket

async def serve(conn):
    conn.setblocking(False)

    await minio.wait_readable(conn)
    data = conn.recv(100)

    await minio.wait_writable(conn)
    conn.sendall(data)

    conn.close()

async def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8888))
    server.listen()
    server.setblocking(False)

    while True:
        await minio.wait_readable(server)
        conn, _ = server.accept()

        await minio.spawn(serve(conn))

minio.run(main())
```

The power of convenient abstractions, huh? But that is it for today.

## Conclusion

We learned a lot today. Of course a proper async runtime has a lot
of other niceties, such as cancellation support, better abstractions
and all the other things you know and love from `asyncio`.

This is by no means complete or *the* reference for the real deal.
But it provides a solid foundation to build upon and has taught you
most of the relevant concepts that also appear in real runtimes.

You can find the full source code for this post
[here](https://gist.github.com/vbe0201/cce570c733c70e06ff62dc60597c5e6d).

Until next time!
