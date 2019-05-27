# imgtool

This is a GitHub-hosted copy of `imgtool`, a tool for working on Android firmware .img files.

# Usage
```
./imgtool _img_name_  [stl=....|extract]
Where: _img_name_ is the name of an Android boot or bootloader image (or boot partition)
       [extract]  is an optional parameter to extract the image components
       [offset=...]  offset to find ANDROID! magic (e.g. 256 in HTC boot)
       [stl=] specifying a list file to reconstruct system.img from

or:     ./imgtool make _img_name_ _kernel_ _ramdisk_ [....]
        Make _img_name by combining kernel and ramdisk and creating header
       [cmdline='args to kernel'] is an optional parameter specifying the kernel command line
       [addr=0x.....] is an optional base address to load the kernel into
```

# Building on Linux

```
git clone https://github.com/kerastinell/imgtool.git
cd imgtool
make
```

# Credits

This tool was created by Jonathan Levin (http://NewAndroidBook.com) and is part of the free downloads for the book "Android Internals: A Confectioner's Cookbook".
