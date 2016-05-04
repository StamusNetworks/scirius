#!/usr/bin/python
import sys
from shutil import copy
from tempfile import NamedTemporaryFile

if len(sys.argv) < 2:
    print >>sys.stderr, 'Usage: %s file [file..]'
    exit(1)

def add_table(fout, table, col_sizes):
    while len(col_sizes) and col_sizes[-1] == 0:
        col_sizes = col_sizes[:-1]

    if len(col_sizes) == 0:
        fout.write('\n')
        return

    for row in table:
        _row = '|'
        for col_no, col_size in enumerate(col_sizes):
            txt = ''
            if col_no < len(row):
                txt = row[col_no].strip()
            _row += ' ' + txt.ljust(col_size) + ' |'
        fout.write(_row + '\n')

for arg in sys.argv[1:]:
    fin = open(arg, 'r')
    fout = NamedTemporaryFile()

    lines = fin.read().splitlines()
    fin.close()

    table = []
    col_sizes = []

    for line in lines:
        if line.startswith('|'):
            row = []
            
            escaped = False
            
            col_no = 0
            for i, col in enumerate(line.split('|')[1:]):
                if escaped:
                    row[-1] = row[-1] + '|' + col
                    escaped = False
                else:
                    row.append(col)

                if len(col_sizes) <= col_no:
                    col_sizes.append(0)

                if len(row[-1].strip()) > col_sizes[col_no]:
                    col_sizes[col_no] = len(row[-1].strip())
    
                if len(col) and col[-1] == '\\':
                    escaped = True
                else:
                    col_no += 1
            table.append(row)
        else:
            if table:
                add_table(fout, table, col_sizes)
                table = []
                col_sizes = []
            fout.write(line + '\n')

    if table:
        add_table(fout, table, col_sizes)

    fout.flush()
    copy(fout.name, arg)
    fout.close()
