#!/usr/bin/env python

# Copyright (c) 2017 Dependable Systems Lab, EPFL
# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

"""
Runs Pylint with some additional checkers.
"""

from __future__ import print_function

import os
import sys
import tokenize

import astroid
from pylint.checkers import BaseChecker, BaseTokenChecker
from pylint.interfaces import IAstroidChecker, ITokenChecker
from pylint.lint import PyLinter
import six


################
# Additional checkers
################

SINGLE_QUOTES = ('\'', '"')
TRIPLE_QUOTES = ('\'\'\'', '"""')

DEFAULT_SINGLE_QUOTE = '\''
DEFAULT_TRIPLE_QUOTE = '"""'


class LiteralQuoteChecker(BaseTokenChecker):
    """
    Check that string literals use a consistent quote character, be it a single
    quote or a double quote.
    """

    __implements__ = ITokenChecker

    name = 'string_literal_quotes'
    msgs = {'C8001': ('Use quote character `%s` for string literals, not '
                      '`%s`',
                      'incorrect-string-literal-quote',
                      'Used when the string literal quote character does not '
                      'match the one specified in the '
                      '`expected-string-literal-quote` option.'),
            'C8002': ('Use `%s` triple-quotes, not `%s`',
                      'incorrect-triple-quotes',
                      'Used when the triple-quotes character does not match '
                      'the one specified in the `expected-triple-quote` '
                      'option.'),
           }
    options = (('expected-string-literal-quote',
                {'type': 'choice', 'metavar': '<\' or ">',
                 'default': DEFAULT_SINGLE_QUOTE, 'choices': SINGLE_QUOTES,
                 'help': 'The default string literal quote character. Must be '
                         'either \' or "'}),
               ('expected-string-triple-quote',
                {'type': 'choice', 'metavar': '<\'\'\' or """>',
                 'default': DEFAULT_TRIPLE_QUOTE, 'choices': TRIPLE_QUOTES,
                 'help': 'The default string triple quote. Must be either '
                         '\'\'\' or """'}),
              )

    def process_tokens(self, tokens):
        for tok_type, token, (start_row, _), _, _ in tokens:
            if tok_type == tokenize.STRING:
                self._process_string_token(token, start_row)

    def _process_string_token(self, token, start_row):
        expected_quote_char = self.config.expected_string_literal_quote
        expected_triple_quotes = self.config.expected_string_triple_quote

        # Adapted from pylint/checkers/strings.py
        for i, c in enumerate(token):
            if c in SINGLE_QUOTES:
                break

        # pylint: disable=undefined-loop-variable
        # We ignore prefix markers like u, b, r
        after_prefix = token[i:]

        # Check triple-quote strings
        if len(after_prefix) >= 3 and after_prefix[:3] in TRIPLE_QUOTES:
            if after_prefix[:3] != expected_triple_quotes:
                self.add_message('incorrect-triple-quotes', line=start_row,
                                 args=(expected_triple_quotes,
                                       after_prefix[:3]))
        # Check single quote strings
        elif after_prefix[0] != expected_quote_char:
            self.add_message('incorrect-string-literal-quote', line=start_row,
                             args=(expected_quote_char, after_prefix[0]))


class StringConcatChecker(BaseChecker):
    """
    Look for string concatenation operations.

    We use a very naive approach and only look for string concatenations that
    contain at least one string literal.
    """

    __implements__ = IAstroidChecker

    name = 'string_concatenation'
    msgs = {'C8003': ('Prefer string substitution to string concatenation',
                      'string-concat',
                      'Used when a string concatenation operation is found.'),
           }

    def visit_binop(self, node):
        if node.op != '+':
            return

        left = node.left
        if (isinstance(left, astroid.Const) and
                isinstance(left.value, six.string_types)):
            self.add_message('string-concat', node=node)


def register(linter):
    linter.register_checker(LiteralQuoteChecker(linter))
    linter.register_checker(StringConcatChecker(linter))


################
# Run pylint
################

FILE_DIR = os.path.dirname(__file__)
THIS_MODULE = os.path.splitext(os.path.basename(__file__))[0]
PYLINT_RC_PATH = os.path.join(os.path.realpath(FILE_DIR), 'pylint_rc')


def main(args):
    if len(args) != 2:
        print('Usage: %s /path/to/python/code' % args[0])
        sys.exit(1)

    # Need to add tis script's directory to the Python path so that this module
    # can be made available to Pylint
    sys.path.append(FILE_DIR)

    linter = PyLinter()

    linter.load_default_plugins()
    linter.load_plugin_modules([THIS_MODULE])

    linter.read_config_file(PYLINT_RC_PATH)
    linter.load_config_file()

    linter.check(args[1])
    linter.generate_reports()


if __name__ == '__main__':
    main(sys.argv)
