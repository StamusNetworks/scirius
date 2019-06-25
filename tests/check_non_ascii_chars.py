#!/usr/bin/python3
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import re
from pathlib import Path


def usage():
    return '''
--------------------------------------------------------------------------------------
---------------------------- Doc: Add an Exception -----------------------------------

Exceptions can be added with the following syntax:
    * React/JS:     {/* ignore_utf8_check: 8226 8214 */}
    * JS:           // ignore_utf8_check: 8226 8214
    * CSS/JS:       /* ignore_utf8_check: 8226 */
    * HTML:         <!-- ignore_utf8_check: 8226 -->
    * Python:       # ignore_utf8_check: 568

ignore_utf8_check:  keyword that allows to disable check
568:                unicode char code

The following line won't throw an exception:
    my_var = ȸ  # ignore_utf8_check: 568
"""

--------------------------------------------------------------------------------------
'''


wrong_chars = False
errors = []
errors.append('--------------------------------------------------------------------------------------')
errors.append('--------------------------------- None Ascii Chars -----------------------------------')

for _type in ('js', 'html', 'css', 'py',):
    for filename in list(Path('.').glob('**/*.%s' % _type)):
        if not filename.is_file():
            continue

        filename = str(filename.resolve())
        if '/node_modules/' not in filename and not filename.endswith('nv.d3.min.js') and 'rules/static/dist/styles.css' not in filename and 'rules/static/bundles' not in filename and 'rules/static/doc' not in filename:
            with open(filename, 'r', encoding='utf-8') as f:
                for idx, line in enumerate(f.readlines(), 1):
                    try:
                        line.encode('ascii')
                    except UnicodeEncodeError:
                        for jdx, c in enumerate(line, 1):
                            try:
                                c.encode('ascii')
                            except UnicodeEncodeError:
                                char = str(ord(c))
                                if 'ignore_utf8_check' in line:
                                    content = line[line.index('ignore_utf8_check'):]
                                    char_code = re.findall('\d+', content)

                                    if char in char_code:
                                        continue

                                errors.append('"%s" (%s):\tLine: %s\tColumn: %s\tFilename: %s' % (c, char, idx, jdx, filename))
                                wrong_chars = True

if not wrong_chars:
    print('\n!! Code is Clean, Congrats !!')
else:
    print('\n'.join(errors))
    print('\n%s' % usage())
    raise Exception('None Ascii chars found')
    # raise Exception('Those chars are not accepted in source files')
