# Unicycle - unikernel application framework

Most modern-day operating systems use the concept of separating applications from the kernel. The kernel has access to the underlying hardware and system resources. If an application needs to access hardware (such as the network or disk), it must request the kernel to perform the action. This separation between kernel space and user space became dominant in the 1960s, when computers were expensive and needed to be shared among many users. It continues to work well for the majority of use cases.

However, performing a context switch between user space and the kernel is not free. Heavily loaded applications that need to perform a large number of input/output operations can spend significant time switching back and forth. But what if the application code lived in the kernel address space, eliminating the need for context switching altogether? What if the application itself took responsibility for managing the hardware directly?

That is the main idea behind unikernel applications. The Unicycle project is a framework for creating such applications. Unicycle provides implementations of core system components such as hardware initialization, drivers, a scalable memory allocator, per-CPU area management, and more—allowing developers to focus on application logic, like processing HTTP or RPC requests. Unicycle applications can run in a QEMU emulator, inside a virtual machine, or directly on bare metal without an operating system.

Unicycle’s configuration system is flexible, allowing you to compile in only the components your application actually needs. Is your application diskless and requires only networking, CPU, and memory? No problem—just disable the disk/SATA subsystem, resulting in a smaller and more efficient application. Another example: if your application doesn’t require multi-CPU support, you can disable SMP. This effectively turns synchronization primitives into no-ops, making the relevant code paths much more optimal.

One limitation of the unikernel architecture is the "one machine – one application" model. This differs from general-purpose operating systems, which run many different processes or applications on the same machine while sharing hardware resources. However, if you examine the architecture of low-latency systems, you’ll see they tend not to share resources between multiple applications. For example, database servers optimized for low-latency processing avoid running a heavily loaded web server on the same machine. Doing so would cause interference and lead to unpredictable latency spikes. Unlike in the 1960s—when computers were rare and expensive—modern systems are cheaper, and system architects now aim to separate applications across machines. For instance, a search engine's storage component might run on one machine, its front-end on another, and its SQL database on a third. These components communicate over network fabrics.

Unicycle does not attempt to replace general-purpose operating systems like Linux or Windows. The goal of a general-purpose OS is to serve a wide range of users and use cases. The goal of Unicycle is to efficiently handle low-latency server workloads.

## Checkout sources
```git clone --recurse-submodules https://github.com/libunicycle/unicycle```

## Build

To build a 'hello world HTTP' application you need to prepare the development environment:

* Install [shog](https://github.com/libunicycle/shog) build system as ```gem install shog-build```.
* Install [ninja build system](https://ninja-build.org/), compiler and linker using your package manager.
* Install [menuconfig](https://github.com/anatol/menuconfig) the UI configuration tool from Linux kernel.

## Configure

Unicycle has a flexible compile-time configuration system that allows to set many different aspects of the application. To lunch configuration process please run ```make config```. If you work with Linux project you'll find the UI similar, in fact it is the same old kconfig tool slightly adopted for unicycle project.

## Build

To build the unicycle example run ```shog```. It will compile the application binary at ```out/app.elf```. It is the binary that contains the hardware-specific logic plus simple bare-meral HTTP server.


## Run

Unicycle allows to build unikernel applications that do not require any operating system. All one need to run such app is a compatible hardware or hardware emulator.

### With QEMU emulator

The easiest way to run a unicycle app is to use QEMU. Unicycle requires a QEMU patch that implements unikernel boot protocol called `uniboot`. Please find the patch here https://github.com/libunicycle/qemu

Once you have the patched version of QEMU you can start the unicycle application as:
`$ ./scripts/run`

### With hardware

While emulators is a great development tool it has non-zero performance overhead. It is more interesting to run unicycle applications at lower level of abstraction - either in a virtual machine or at a bare hardware.

First you need to create a bootable USB drive with a bootloader that understands
how to load and run bare-metal unicycle applications. [Unicycle bootloader](https://github.com/libunicycle/bootloader) is the one and it serves the same role as GRUB bootloader for Linux kernel.

The unicycle bootloader supports two modes:
  - load unicycle app from the same bootable USB flash
  - load unicycle app from network

The network option is easier for development and the rest of the section briefly explains how to set it up.
```
# compile the bootloader binaries
$ cd bootloader
$ make

# create the bootlable image
$ sudo ./image_generate.sh

# flash the image to the a USB
# sudo dd if=boot.img of=/dev/hdXXXX bs=1M
```

Now it is time to find a motherboard you plan to use for development. Currently only Intel platform is supported. One possible option is [ASUS Q170M](https://www.asus.com/Motherboards/Q170M-C/) that has a great UEFI support and work perfectly with unicycle. Configure the motherboard to boot from USB, enable network support option and then insert the bootable USB and turn on the computer.

At host you need to compile the unicycle app and then run [bootserver](https://github.com/libunicycle/bootserver). The motherboard will start the bootloader, pull unicycle binaries from the host machine and then start executing the application.

Then open `http://10.0.0.45/` in your browser and you'll see 'Hello, world!' greeting web page served by our unicycle app.

## Load testing

Unicycle is its early days of development but nevertheless it is a great idea to track its performance metrics. Here is a simple load test for the 'hello world' HTTP server implemented with `unicycle`. We run the stress test with 20000 HTTP request per second. The application is compile as single-threaded. 230 microseconds mean response time, it is pretty impressive...

The hardware setup is following: 'Host with Linux' <-> '1GB ethernet bridge' <-> 'ASUS Q170M motherboard as DUT'.

```
$ echo "GET http://10.0.0.45/" | vegeta attack -duration=20s -rate=20000 | tee results.bin | vegeta report
Requests      [total, rate]            400000, 19999.99
Duration      [total, attack, wait]    20.000238037s, 20.000006542s, 231.495µs
Latencies     [mean, 50, 95, 99, max]  230.239µs, 228.393µs, 255.713µs, 387.238µs, 4.562508ms
Bytes In      [total, mean]            19200000, 48.00
Bytes Out     [total, mean]            0, 0.00
Success       [ratio]                  100.00%
Status Codes  [code:count]             200:400000
Error Set:
```
