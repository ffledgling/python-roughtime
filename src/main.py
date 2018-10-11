#!/usr/bin/env python3

import socket
import struct
import pprint
import datetime

# https://pypi.org/project/ed25519/
# https://github.com/warner/python-ed25519
# https://blog.mozilla.org/warner/2011/11/21/introducing-python-ed25519/
import ed25519

def print_protocol_packet(packet):
    print(type(packet))
    print(packet)
    print(packet.hex())
    print("*"*80)
    for i in range(0, len(packet), 4):
        print(packet[i:i+4], ":", "0x" + packet[i:i+4].hex())

def deconstruct_SREP(section):

    #print("SREP is:", section)
    radius = struct.unpack('<L', section[b'RADI'])[0]
    midpoint = struct.unpack('<Q', section[b'MIDP'])[0]

    print("Time is:", midpoint, "±", radius, "µs (UTC)")
    print("Local Time:", datetime.datetime.fromtimestamp(midpoint/10**6), "±", datetime.timedelta(microseconds=radius))

def verify_cert(packet):

    print('Verifying CERT')
    pprint.pprint(packet)

    vk = ed25519.VerifyingKey(SERVER_PUBKEY, encoding='base64')
    try:
        vk.verify(sig=packet[b'SIG\x00'], msg=(CERTIFICATE_CONTEXT + packet[b'DELE']))
        print("Successfully verified cert")
    except ed25519.BadSignatureError:
        print("Could not verify server certificate")
        raise


def deconstruct_resp(packet):
    # TODO: We're not handling the case of 
    # first 4 bytes is num_tags, next 4*(num_tags-1) bytes are offsets, then 4*num_tags bytes are tag names
    # Then we have the contents after that
    #print('Response Length:', len(packet))
    num_tags = struct.unpack('<L', packet[:4])[0]
    #print("Number of tags:", num_tags)
    tag_end = 4*num_tags+4*num_tags
    tags = struct.unpack('<' + '4s'*num_tags, packet[4*num_tags:4*num_tags+4*num_tags])
    #print(tags)
    body = packet[tag_end:]
    # We iterate over the offsets, if there are any
    offsets = struct.unpack('<' + 'L'*(num_tags-1), packet[4:4*num_tags])
    #print(offsets)

    starts = tuple([0] + list(offsets) + [len(body)])
    #print("Starts:", starts)

    data = {}
    for i,tag in enumerate(tags):
        data[tag] = body[starts[i]:starts[i+1]]

    #print(data)
    pprint.pprint(data)

    if b'SREP' in data:
        time_struct = deconstruct_resp(data[b'SREP'])
        deconstruct_SREP(time_struct)

    if b'CERT' in data:
        cert = deconstruct_resp(data[b'CERT'])
        cert_dele = deconstruct_resp(cert[b'DELE'])
        #cert[b'DELE'] = cert_dele
        verify_cert(cert)

    return data


SERVER_FQDN='roughtime.cloudflare.com'
SERVER_PORT=2002
SERVER_PUBKEY='gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo='

# These are prefixes apparently required when running verification
# Not mentioned in the spec, but part of Google's own implementation of the protocol
# https://roughtime.googlesource.com/roughtime/+/master/go/protocol/protocol.go#36
# https://github.com/cloudflare/roughtime/blob/master/vendor/roughtime.googlesource.com/roughtime.git/go/protocol/protocol.go#L36-L37
CERTIFICATE_CONTEXT=b'RoughTime v1 delegation signature--\x00'
SIGNED_RESPONSE_CONTEXT=b'RoughTime v1 response signature\x00'


SERVER = (SERVER_FQDN, SERVER_PORT)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
"""
https://roughtime.googlesource.com/roughtime/+/master/PROTOCOL.md

We're not using any offsets in the simplest case

1 # num_tags
64 # Size of offset (from where tags finish) for PAD\xff
NONC # tagname
PAD\xff # tagname for pading a UDP packet
TESTREQ\x00 # tag value
\x00 ... upto 1024 bytes of the packet
"""

# TODO: add more checks for padding and string length correctly here
byte_format_string = '<LL4s4s8s'
simple_message = (2, 64, b'NONC', b'PAD\xff', b'TESTREQ'.ljust(64, b'\xff'))

message = struct.pack(byte_format_string, *simple_message)

#print_protocol_packet(message)

#print(len(message))

message = message.ljust(1024, b'\x00')

#print(len(message))
#print(message)

sock.settimeout(10.0)
status = sock.sendto(message ,SERVER)
#print("Status:", status)

resp = sock.recv(1024)
#print(type(resp))
#print_protocol_packet(resp)
deconstruct_resp(resp)
