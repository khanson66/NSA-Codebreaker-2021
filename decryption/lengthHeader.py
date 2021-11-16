import numpy
length = 0x87
length_header= 0x09ce
size2 = 0xf6bd

size1 = length_header
#size2 = ((length - size1) + 0x10000)
length = (size2 - 0x10000) + size1


length_header = length_header & 0xffff | numpy.uint(size2) << 0x10

print(hex(size1),hex(size2))
print(hex(length_header))
print(hex(length))