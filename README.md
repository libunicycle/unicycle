# Unicycle - unikernel application framework

Most modern day operating systems use idea of separating applications from kernel. Kernel has access to underlying hardware and resources. If some application needs access to the hardware (like network or disk) then it asks kernel to perform the action. Such separation to kernel vs userspace became dominant in 60s when computers were expensive and need to be shared between large number of users. And it works well for majority of use-cases.

Though performing a context switch between userspace and kernel to make an action is not free. Heavy-loaded applications that need to make a large number of input/output operations spend quite a lot of time switching back and forth. But what if the application code lived in the kernel address space and thus the context switch can be avoided altogether? What if the application itself will take responsibilities on managing hardware directly?

That is the main idea behind unikernel applications. And Unicycle project is a framework to create such applications. Unicycle provides implementation for base system components: hardware initialization, drivers, scalable memory allocator, per-cpu area management, etc.. and let developers focus on the application logic like processing HTTP or RPC requests. Unicycle applications can be run at QEMU emulator, in a virtual machine or straight at a hardware without any operating system. Unicycle framework configuration system is flexible and allows to compile-in only those components that are needed for your application. Is your application disk-less and needs network+cpu+memory only? No problem, just disable disk/SATA subsystem and you have smaller and more optimal application. Another example is if your application does not require multi-CPU then SMP can be disabled. It turns synchronization primitives to no-op thus making this codepath much more optimal.

One limitation of unikernel architecture is "one machine - one application" rule. It differs from general purpose OS that have many different process/apps running on the same machine and actively sharing the hardware resources. But in fact if you look at the architecture of low-latency systems you'll see that they tend **not** to share machine resources between several applications. For example database servers that target low-latency processing avoid running heavy-loaded web server at the same machine. Otherwise they introduce interference to each other with unpredictable long latency tails. Unlike 60s when computers were rare and expensive nowadays computers are cheaper and system architects try to separate applications to different machines - e.g. search engine storage is running at one machine, search engine front-end at another machine, SQL database at a third one. Then applications exchange data over the network fabrics.

Unicycle does not try to replace generic OS like Linux or Windows. The goal of generic OS is to be good enough for majority users and its use-cases. The goal of Unicycle is to handle low-latency server workloads efficiently.

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