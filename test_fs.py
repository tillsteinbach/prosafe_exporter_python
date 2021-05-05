import os

filename = 'test_file_for_fs_test'
teststring = 'test'
if os.path.isfile(filename):
    os.remove(filename)
with open(filename, 'w') as f:
    f.write(teststring)

with open(filename, 'r') as f:
    assert f.read() == teststring
