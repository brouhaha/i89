#!/usr/bin/python3
# Expression parser
# Copyright 2016 Eric Smith <spacewar@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU General Public License
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This file is based on the SimpleCalc.py for pyparsing


from pyparsing import Combine, Forward, Literal, OneOrMore, Optional, \
    ParseException, StringEnd, Word, ZeroOrMore, \
    alphas, alphanums, hexnums, nums

class ExpressionParser:

    operators = { '+': (lambda a,b: a + b),
                  '-': (lambda a,b: a - b),
                  '*': (lambda a,b: a * b),
                  '/': (lambda a,b: a // b) }

    def push_first(self, str, loc, toks):
        self.expr_stack.append(toks[0])
        
    def __init__(self, symtab):
        self.symtab = symtab

        plusorminus = Literal('+') | Literal('-')

        dec_int = Combine(Optional(plusorminus) + Word(nums)) \
                  .setParseAction(lambda t: int(''.join(t)))

        hex_int = Combine(Word(nums, hexnums) + Word('hH')) \
                  .setParseAction(lambda t: int((''.join(t))[:-1], 16))

        ident = Word(alphas, alphanums + '_@?')  # XXX and maybe dollar sign?

        lpar = Literal('(').suppress()
        rpar = Literal(')').suppress()
        addop = Literal('+') | Literal('-')
        multop = Literal('*') | Literal('/')

        expr = Forward()

        factor = ((hex_int | dec_int | ident).setParseAction(self.push_first) |
                  (lpar + expr.suppress() + rpar)
                 )
    
        term = factor + ZeroOrMore((multop + factor).setParseAction(self.push_first))

        expr << term + ZeroOrMore((addop + term).setParseAction(self.push_first))

        self.pattern = expr + StringEnd()

    def parse(self, s):
        self.expr_stack = []
        #try:
        self.pattern.parseString(s)
        #except ParseException:
        #   raise SomeOtherException    
        return self.expr_stack

    def evaluate(self, stk):
        op = stk.pop()
        if op in self.operators:
            right_operand = self.evaluate(stk)
            left_operand = self.evaluate(stk)
            # XXX Currently using None for expressions that contain
            #     undefined symbols.  We might want to change that
            #     to a singleton UndefinedExpression or something.
            if left_operand is None or right_operand is None:
                return None
            return self.operators[op](left_operand, right_operand)
        elif type(op) is str:
            if op in self.symtab:
                return self.symtab[op]
            else:
                return None
        else:
            return op


if __name__ == '__main__':
    symtab = { 'a': 3,
               'b': 5 }
    ep = ExpressionParser(symtab)

    while True:
        try:
            estr = input('> ')
        except EOFError:
            break
        estk = ep.parse(estr)
        print(ep.evaluate(estk))

