#!/usr/bin/python3

ori_sh = """
31c031c9b001b106
5150bb86625556ffd331c95150ffd3b1055150ff
d331c95150ffd331c95150ffd3b1015150ffd3
"""

sh = ori_sh.replace("\n", "")

length  = int(len(sh)/2)
print("Length of the shellcode: {}".format(length))
s = 'shellcode= (\n' + '   "'
for i in range(length):
    s += "\\x" + sh[2*i] + sh[2*i+1]
    if i > 0 and i % 16 == 15: 
       s += '"\n' + '   "'
s += '"\n' + ").encode('latin-1')"
print(s)



