grammar Constraints;

// Parser rules
constraints: statement+;
statement: 'State' 'ID:' INTEGER_VALUE arrayDeclaration* query;
query: '(' 'query' '[' expression+ ']' false_array var_array ')';

false_array: 'false' '[' ']';
var_array: '[' normal_variable* ']';

expression: operator dataType? expression+
            | parentExpression
            | aliasExpression
            | element
            ;

element: variable
        | alias
        | literal
        ;

operator: 'ReadLSB'
        | 'Read'
        | 'Eq'
        | 'Sle'
        | 'And'
        | 'Or'
        | 'LShr'
        | 'ZExt'
        | 'Select'
        ;

aliasExpression: alias ':' parentExpression;
parentExpression: '(' expression ')';
alias: 'N' INTEGER_VALUE;

indexBuffer: '[' (indexPair  ',')* indexPair ']' ;
indexPair: HEX_VALUE '=' HEX_VALUE ;
buffer: '[' (HEX_VALUE)+ ']' ;

arrayDeclaration: 'array' normal_variable '[' length ']' ':' dataType '->' dataType '=' ('symbolic' | buffer);
literal: integerValue | 'false' | 'true';
length: INTEGER_VALUE;
integerValue: INTEGER_VALUE | HEX_VALUE;
variable: normal_variable | array_variable;
array_variable: indexBuffer atOp normal_variable;
normal_variable: VARIABLE;
dataType: W32 | W8;
atOp: '@';

W32: 'w32';
W8: 'w8';
HEX_VALUE: '0x' [0-9A-Fa-f]+;
INTEGER_VALUE: [0-9]+;
VARIABLE: [a-z] [0-9A-Za-z_]+;
WS: [ \t\r\n]+ -> skip;

