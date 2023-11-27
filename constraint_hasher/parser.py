from antlr4 import *  # noqa, type: ignore, pylint: disable=wildcard-import
from antlr4 import CommonTokenStream, InputStream  # noqa, type: ignore

from gen.ConstraintsParser import ConstraintsParser  # type: ignore
from gen.ConstraintsLexer import ConstraintsLexer  # type: ignore

from typing import Optional
import sys

import hashlib

def deterministic_hash(value):
    string_repr = repr(value)
    return hashlib.sha256(string_repr.encode()).hexdigest()


def parse_string(string: str) -> Optional[ConstraintsParser.ConstraintsContext]:
  input_stream = InputStream(string)
  return _parse_stream(input_stream)


def _parse_stream(input_stream) -> Optional[ConstraintsParser.ConstraintsContext]:
  lexer = ConstraintsLexer(input_stream)
  stream = CommonTokenStream(lexer)
  parser = ConstraintsParser(stream)
  tree = parser.constraints()
  print(tree.toStringTree(recog=parser))
  return None if parser.getNumberOfSyntaxErrors() > 0 else tree

def hash_expr(obj: ConstraintsParser.ExpressionContext) -> int:
    if obj.operator():
        operator = obj.operator().getText()
        dataType = ""
        if obj.dataType():
            dataType = obj.dataType().getText()
        expr_list = [deterministic_hash(operator), deterministic_hash(dataType)] + [hash_expr(expr) for expr in obj.expression()]
        return deterministic_hash(tuple(sorted(expr_list)))
    elif obj.parentExpression():
        return hash_expr(obj.parentExpression().expression())
    elif obj.aliasExpression():
        return hash_expr(obj.aliasExpression().parentExpression().expression())
    else:
        return hash_element(obj.element())

def hash_element(element: ConstraintsParser.ElementContext) -> int:
    return deterministic_hash(element.getText())


if __name__ == "__main__":
    with open(sys.argv[1], "r") as f:
        content = f.read()

    tree =parse_string(content)
    for i in tree.expression():
        print(f"Hash of {i.getText()} is {hash_expr(i)}")

