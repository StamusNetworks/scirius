#!/usr/bin/python3
import logging
import os
import re
import subprocess
import sys

from copy import copy


ESLINT = 'hunt/node_modules/eslint/bin/eslint.js'

logging.basicConfig(level=logging.INFO)


def es_check(filename, content):
    backup = filename + '.backup'
    os.rename(filename, backup)

    f = open(filename, 'a')
    f.write(content + '\n')
    f.close()

    logging.debug('running: %s -c .eslintrc --max-warnings 0 %s 2>&1 >/dev/null' % (ESLINT, filename))
    r = subprocess.call('%s -c .eslintrc --max-warnings 0 %s 2>&1 >/dev/null' % (ESLINT, filename), shell=True)  # noqa: DUO116
    logging.debug('eslint rc %d' % r)

    os.unlink(filename)
    os.rename(backup, filename)
    return r != 0


def show_error(f, line_no, check=None):
    line_no += 1
    if check:
        print('%s:%i Useless check %s' % (f, line_no, check))
    else:
        print('%s:%i Useless global check' % (f, line_no))


def check_file(filename):
    f = open(filename)
    original_content = f.read()
    lines = original_content.splitlines()

    for line_no, line in enumerate(lines, 0):
        line = line.strip()

        if 'eslint-disable' in line:
            eslint_kw = re.search(r'(eslint-disable[^ ]*)', line)
            eslint_kw = eslint_kw.group(0)
            terms = line.split(eslint_kw, 1)
            logging.debug('%s:%i terms %s' % (filename, line_no, terms))
            exceptions = re.split('[ ,]', terms[1])
            exceptions = list(filter(lambda x: x != '', exceptions))

            post_terms = ''

            for j, exc in enumerate(exceptions):
                if not re.match(r'[a-zA-Z0-9/_-]+$', exc):
                    logging.debug('end of except "%s"' % exc)
                    post_terms = ' ' + ' '.join(exceptions[j:])
                    exceptions = exceptions[:j]
                    break

            logging.debug('post terms %s' % post_terms)
            logging.debug('checking exceptions %s' % exceptions)

            if len(exceptions) < 2:
                content = copy(lines)
                content.pop(line_no)
                if not es_check(filename, '\n'.join(content)):
                    if len(exceptions):
                        show_error(filename, line_no, exceptions[0])
                    else:
                        show_error(filename, line_no)
                continue

            for j, exc in enumerate(exceptions):
                new_exceptions = copy(exceptions)
                new_exceptions.pop(j)

                _terms = terms[0] + eslint_kw + ' ' + ','.join(new_exceptions) + post_terms
                content = '\n'.join(lines[:line_no] + [_terms] + lines[line_no + 1:])
                if not es_check(filename, content):
                    show_error(filename, line_no, exc)


for arg in sys.argv[1:]:
    check_file(arg)
