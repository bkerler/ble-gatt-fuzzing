# BLE GATT Fuzzing

## Introduction

This repository contains the tool developed to fuzz Bluetooth Low Energy (BLE) GATT layer with over-the-air communication. It is based on attack scenarios which can be found on the related [paper](link/to/paper). The tool relies on the *[WHAD](https://whad.io)* framework and adheres to BLE specification version 4.2.

Proof of Concepts for Denial of Service on Sony *WH-1000XM4* and *WF-1000XM4* are also provided.

A blog post explaining the work that has been done can be found at https://blog.quarkslab.com/my_blogpost.html.

## Installation

To use this fuzzer, ensure that you are working within a Python virtual environment where you have installed the required libraries.

```
$ python3 -m virtualenv venv
$ . ./venv/bin/activate
$ pip3 install -r requirements.txt
```

By default, interacting with most *WHAD*-compatible devices require root permissions.  
Please follow the instructions given by the [documentation](https://whad.readthedocs.io/en/latest/install.html) to be able to interact with your device as a normal user.   

## Usage

To run the tool, you have to provide at least:

- the BLE address of the target,
- if the address is random of not.

The `--help` option displays the following message:
```
Usage: __main__.py [OPTIONS] {client|server}

    Bluetooth Low Energy GATT Fuzzer based on multiple scenario.

Options:
    --bt_addr -bt         Bluetooth address of the device.
    --is_addr_random -r   Is the given Bluetooth address random.
    --post_url -u         Ntfy address to use.
    --interface -i        Interface to use.
    --gatt_handle -g      The last GATT handle of the device.
    --scenario -s         The scenario to play.
    --none-cnt -nc        The maximum number of unreceived responses before triggering an error.
    --prep_write_max -pwm The maximum number of prepare write request PDUs to send.
    --help -h             Show this help message and exit.
```

**Note: The scenario number 8 was removed since it corresponds to the combination of scenarios 4, 5 and 9.**

### Example

The following command run the scenario number `1` on the device with the `random` BLE address `a8:42:e3:ca:bf:fe` using the `hci1` interface.
```
$ python __main__.py -bt a8:42:e3:ca:bf:fe -r True -i hci1 -s 1 client
```

## PoCs

There are two behaviors with these PoCs:

- The crash of the device,
- The crash of the GATT server and the need to restart the headset to have the GATT server on.  

The headset will take some time to be able to be restarted.

To run the PoCs, you have to edit them with your own device's BLE address.

```
$ python wh_xm4_poc.py
$ python wf_xm4_poc.py
```

**The probability of success is low and the PoCs may need to be run several times before the crashs occur.**