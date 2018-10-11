Python Roughtime
================

WIP python client for the [roughtime protocol](https://roughtime.googlesource.com/roughtime/+/master/PROTOCOL.md).

Packet Structure
----------------

<!-- Just use vim-table-mode or similar here, it's not worth maintaing this table by hand -->
All values in the protocol *must* be little endian. Take care when encoding and decoding integers, strings etc.

| Field/Section | Offset                | Length (in bytes)      | Type   | Values           | Description                                                                                                                                                                                                                                                                                                                                                                                                                             |
|---------------|-----------------------|------------------------|--------|------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| tag_num       | 0                     | 4                      | uint32 | [0, 2**32)       | Lists the number of tags defined the packet                                                                                                                                                                                                                                                                                                                                                                                             |
| offset(s)     | 4                     | [0, 4*(tag_num-1))     | uint32 | [0, len(packet)) | Offset table indicating the start of every sub-section (denoted by a tag) in the *body* of the packet (i.e offsets from the end of the protocol header). In cases where the `tag_num` is 0 or 1, the offset section maybe entirely ommitted since the meaning is obvious. Implication: The *first* value in the offset table always indicates the start of the *second* tag. Valid Roughtime packets always have at least two sections. |
| tag(s)        | 4*(tag_num)           | [0, 4*(tag_num)        | uint32 | Anything         | Name/identifier for a particular subsection in the packet. The roughtime protocol specifies predefined sections for different types of interactions                                                                                                                                                                                                                                                                                     |
| body          | 4 + 4*(2*tag_num - 1) | [0,1024 - len(header)) | *      | Anything         | Binary blob of data to be indexed in using offsets and tags. The interpretation of the data is based on the meaning assigned to sections (out of band)                                                                                                                                                                                                                                                                                  |


Official References
-------------------

* Protocol Description: <https://roughtime.googlesource.com/roughtime/+/master/PROTOCOL.md>
* Roughtime Implementation by Google: <https://roughtime.googlesource.com/roughtime/+/master/>
* Cloudflare's Implementation: <https://github.com/cloudflare/roughtime>

Extra Reading
-------------

* Signatures vs Decryption in cryptography I: <https://crypto.stackexchange.com/a/9897/62507>
* Signatures vs Decryption in cryptography II: <https://www.cs.cornell.edu/courses/cs5430/2015sp/notes/rsa_sign_vs_dec.php>
* How does a public key verify a signature? <https://stackoverflow.com/q/18257185/1220089>
* "how digital signature verification process works" (sic) <https://security.stackexchange.com/a/8039/17500>
