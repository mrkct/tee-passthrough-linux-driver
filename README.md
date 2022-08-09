**Note: this is not yet implemented. Check back later**

# Fake-TEE
Fake-TEE is a Linux kernel module that creates a fake Trusted Execution
Environment (TEE) using Linux's TEE subsystem without having the actual
required hardware.
This TEE offers a single Trusted Applications (TA) for testing purposes (an
increment number procedure), this project is only useful for allowing someone
to play around with Linux's TEE subsystem without actually having the
necessary hardware or running an emulator.

## How to use it

### 1. Ensure the TEE subsystem module is on
First of all you need to check if the kernel you're running was compiled with
the TEE subsystem. To do that run:

        grep /boot/config.$(uname -r) CONFIG_TEE

Based on what this commands says:
  * `y`: Your kernel was compiled with the TEE subsystem as a static module, you don't need to do anything and you can go to the next step
  * `m`: Your kernel was compiled with the TEE subsystem as a separate module, you first need to load this module. To do that run:

      sudo insmod /lib/modules/$(uname -r)/kernel/drivers/tee/tee.ko`
  
  * `n`: Your kernel was compiled without the TEE subsystem, you'll need to compile and install a new kernel with the TEE subsystem activated.

### 2. Compile this kernel module
Once you're sure you are running the TEE's subsystem module you'll have to compile this project. Run these commands:

        git clone https://github.com/mrkct/fake-tee.git
        cd fake-tee/src
        make all

### 3. Load the module

The compiled kernel module is `faketee.ko`, you can load it using `insmod` like this:

        sudo insmod faketee.ko

Now look in your `/dev` directory, you should see a new TEE device (probably `/dev/tee0`). You can read the module's log by using `sudo dmesg`. When you're done with the device you can remove it by typing `sudo rmmod faketee`.

Note that you will have to do steps 1 and 3 every next time you boot up your computer.

The folder `/tests` has some small programs that make some requests to a TEE, to try them out run

    cd tests
    make all
    ./print_tee_id /dev/tee0

# Developing on VSCode
If you're working on this module with VSCode you can add the following to your `c_cpp_properties.json`
file so that you can get working autocompletition. You'll probably have to change the
`linux-headers-5.13.0-51` part to the one you have:


        "includePath": [
                "${workspaceFolder}/**",
                "/usr/local/include",
                "/usr/src/linux-headers-5.13.0-51/include/",
                "/usr/src/linux-headers-5.13.0-51-generic/include/",
                "/usr/src/linux-headers-5.13.0-51-generic/arch/x86/include",
                "/usr/src/linux-headers-5.13.0-51-generic/arch/x86/include/uapi",
                "/usr/src/linux-headers-5.13.0-51-generic/arch/x86/include/generated"
        ],
        "defines": [
                "__GNUC__",
                "__KERNEL__",
                "MODULE"
        ],