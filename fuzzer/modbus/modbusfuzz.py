#!/usr/bin/env python3

from boofuzz import *

def main():
    session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 5020)),
                      restart_threshold=1, restart_timeout=1.0)

    ##
    # Modbus TCP header:
    # * 2-byte transaction id
    # * 2-byte protocol id, must be 0000
    # * 2-byte message length
    # * 1 byte unit ID
    #
    # followed by request data:
    # * 1 byte function ID
    # * 2-byte starting address
    # * 2-byte number of registers
    s_initialize(name="Read Input Registers")

    if s_block_start("header"):
        # Transaction ID
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="transaction_id")
        # Protocol ID. Fuzzing this usually doesn't provide too much value so let's leave it fixed.
        # We can also use s_static here.
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="proto_id", fuzzable=False)
        # Length. Fuzzing this is generally useful but we'll keep it fixed to make this tutorial's
        # data set easier to explore.
        s_bytes(value=bytes([0x00, 0x06]), size=2, max_len=2, name="len", fuzzable=False)
        # Unit ID. Once again, fuzzing this usually doesn't provide too much value.
        s_bytes(value=bytes([0x01]), size=1, max_len=1, name="unit_id", fuzzable=False)
    s_block_end()

    if s_block_start("data"):
        # Function ID. Fixed to Read Input Registers (04)
        s_bytes(value=bytes([0x04]), size=1, max_len=1, name="func_id", fuzzable=False)
        # Address of the first register to read
        s_bytes(value=bytes([0x00, 0x00]), size=2, max_len=2, name="start_addr")
        # Number of registers to read
        s_bytes(value=bytes([0x00, 0x01]), size=2, max_len=2, name="reg_num")
    s_block_end()

    session.connect(s_get("Read Input Registers"))

    session.fuzz()

if __name__ == "__main__":
    main()