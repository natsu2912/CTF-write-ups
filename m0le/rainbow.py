#!/usr/bin/python3

from string import printable
from hashlib import sha256
from tqdm.auto import tqdm
mapper = {}
for c1 in tqdm(printable):
    c = c1
    mapper[sha256(c.encode('ascii')).hexdigest()[-6:]] = c
    for c2 in printable:
        c = c1 + c2
        mapper[sha256(c.encode('ascii')).hexdigest()[-6:]] = c
        for c3 in printable:
            c = c1 + c2 + c3
            mapper[sha256(c.encode('ascii')).hexdigest()[-6:]] = c
            for c4 in printable:
                c = c1 + c2 + c3 + c4
                mapper[sha256(c.encode('ascii')).hexdigest()[-6:]] = c

import pickle
with open('hashtable', 'wb') as dict_file:
    pickle.dump(mapper, dict_file)
