# R0fuzz <!-- omit in toc -->
[![LICENSE](https://img.shields.io/badge/License-MIT-green)](https://github.com/AshwAthi8/Project-NetwoFuz/blob/master/LICENSE)

## Overview <!-- omit in toc -->

![r0fuzz - logo](https://github.com/AshwAthi8/r0fuzz/blob/master/images/logo4.gif)

Finding security flaws effectively and efficiently in Industrial Control Systems is of great importance as such systems are used in various important industries like nuclear power plants. *r0fuzz* aims to find security flaws in the hardware network protocols like MODBUS, DNP3 etc.

## Table of Contents <!-- omit in toc -->

- [1. Working](#1-working)
- [2. Installation](#2-installation)
  - [2.1. Dependencies](#2.1-dependencies)
- [3. Usage](#3-usage)
- [4. Features](#4-features)
- [5. TODO](#5-todo)

## 1. Working

Work flow of the tool -
 ![r0fuzz - daigram](https://github.com/AshwAthi8/r0fuzz/blob/master/images/our_fuzzer.png)


## 2. Installation

Here are the installation instructions for r0fuzz

- Clone the repo
 ```shell
 git clone https://github.com/ais2397/r0fuzz.git
 cd r0fuzz
 ```
- Install the python dependencies using 

```shell
pip3 install -r requirements.txt
```

## 3. Usage
```shell
usage: r0fuzz.py [-h] -s SEED -t TARGET [-d] [-v]

optional arguments:
  -h, --help            show this help message and exit
  -s SEED, --seed SEED  sample input file
  -t TARGET, --target TARGET
                        target protocol
  -d, --dumb            Dumb fuzz the target
  -v, --verbosity       Log level
```

 To run r0fuzz.py:
```shell
python3 r0fuzz.py -s <relative_path_of_seed_packet> -t <target_protocol> -vv
```
## 4. Features
- Basic Fuzzer using brute force approach
- Smart Fuzzer
  - Mutation based
  - Generation based
- Current support
  - MODBUS
  - DNP3


## 5. TODO
- Enhance the fuzzer.
- Incorporate other protocols.


