import collections
import enum
import logging
import sys

import ply.lex as lex
import ply.yacc as yacc

# Appears that Ply needs to read the source, so disable bytecode.
sys.dont_write_bytecode

# Initialize the logger
logger = logging.getLogger(__name__)

MetaElement = collections.namedtuple('MetaElement', ['key', 'value'])
StringsElement = collections.namedtuple('StringsElement', ['key', 'value'])


class ElementTypes(enum.Enum):
    """An enumeration of the element types emitted by the parser to the interpreter."""

    RULE_NAME = 1
    METADATA_KEY_VALUE = 2
    STRINGS_KEY_VALUE = 3
    STRINGS_MODIFIER = 4
    IMPORT = 5
    TERM = 6
    SCOPE = 7
    TAG = 8
    INCLUDE = 9


class ParserInterpreter:
    """Interpret the output of the parser and produce an alternative representation of Yara rules."""

    def __init__(self, log_level=logging.ERROR):
        """Initialize the parser object."""
        self.rules = list()

        self.current_rule = dict()

        self.string_modifiers = list()
        self.imports = list()
        self.includes = list()
        self.terms = list()
        self.scopes = list()
        self.tags = list()

        logger.setLevel(log_level)

    def addElement(self, elementType, elementValue):
        """Accept elements from the parser and uses them to construct a representation of the Yara rule."""
        if elementType == ElementTypes.RULE_NAME:
            self.current_rule['rule_name'] = elementValue

            self.readAndResetAccumulators()

            self.rules.append(self.current_rule)
            logger.debug('Adding Rule: {}'.format(self.current_rule['rule_name']))
            self.current_rule = dict()

        elif elementType == ElementTypes.METADATA_KEY_VALUE:
            if 'metadata' not in self.current_rule:
                self.current_rule['metadata'] = {elementValue.key: elementValue.value}
            else:
                if elementValue.key not in self.current_rule['metadata']:
                    self.current_rule['metadata'][elementValue.key] = elementValue.value
                else:
                    if isinstance(self.current_rule['metadata'][elementValue.key], list):
                        self.current_rule['metadata'][elementValue.key].append(elementValue.value)
                    else:
                        self.current_rule['metadata'][elementValue.key] = [self.current_rule['metadata'][elementValue.key], elementValue.value]

        elif elementType == ElementTypes.STRINGS_KEY_VALUE:
            string_dict = {'name': elementValue.key, 'value': elementValue.value}

            if any(self.string_modifiers):
                string_dict['modifiers'] = self.string_modifiers
                self.string_modifiers = list()

            if 'strings' not in self.current_rule:
                self.current_rule['strings'] = [string_dict]
            else:
                self.current_rule['strings'].append(string_dict)

        elif elementType == ElementTypes.STRINGS_MODIFIER:
            self.string_modifiers.append(elementValue)

        elif elementType == ElementTypes.IMPORT:
            self.imports.append(elementValue)

        elif elementType == ElementTypes.INCLUDE:
            self.includes.append(elementValue)

        elif elementType == ElementTypes.TERM:
            self.terms.append(elementValue)

        elif elementType == ElementTypes.SCOPE:
            self.scopes.append(elementValue)

        elif elementType == ElementTypes.TAG:
            self.tags.append(elementValue)

    def readAndResetAccumulators(self):
        """Add accumulated elements to the current rule and resets the accumulators."""
        if any(self.imports):
            self.current_rule['imports'] = self.imports
            self.imports = list()

        if any(self.includes):
            self.current_rule['includes'] = self.includes
            self.includes = list()

        if any(self.terms):
            self.current_rule['condition_terms'] = self.terms
            self.terms = list()

        if any(self.scopes):
            self.current_rule['scopes'] = self.scopes
            self.scopes = list()

        if any(self.tags):
            self.current_rule['tags'] = self.tags
            self.tags = list()

# Create an instance of this interpreter for use by the parsing functions.
parserInterpreter = ParserInterpreter()


def parseString(inputString):
    """Take a string input expected to consist of Yara rules, and returns a list of dictionaries that represent them."""
    # Run the PLY parser, which emits messages to parserInterpreter.
    parser.parse(inputString)

    return parserInterpreter.rules


########################################################################################################################
# LEXER
########################################################################################################################
tokens = [
    'BYTESTRING',
    'STRING',
    'REXSTRING',
    'EQUALS',
    'STRINGNAME',
    'STRINGNAME_ARRAY',
    'LPAREN',
    'RPAREN',
    'LBRACK',
    'RBRACK',
    'LBRACE',
    'RBRACE',
    'ID',
    'BACKSLASH',
    'FORWARDSLASH',
    'PIPE',
    'PLUS',
    'SECTIONMETA',
    'SECTIONSTRINGS',
    'SECTIONCONDITION',
    'COMMA',
    'STRINGCOUNT',
    'GREATERTHAN',
    'LESSTHAN',
    'GREATEREQUAL',
    'LESSEQUAL',
    'PERIOD',
    'COLON',
    'STAR',
    'HYPHEN',
    'AMPERSAND',
    'NEQUALS',
    'EQUIVALENT',
    'DOTDOT',
    'HEXNUM',
    'NUM'
]

reserved = {
    'all': 'ALL',
    'and': 'AND',
    'any': 'ANY',
    'ascii': 'ASCII',
    'at': 'AT',
    'contains': 'CONTAINS',
    'entrypoint': 'ENTRYPOINT',
    'false': 'FALSE',
    'filesize': 'FILESIZE',
    'for': 'FOR',
    'fullword': 'FULLWORD',
    'global': 'GLOBAL',
    'import': 'IMPORT',
    'in': 'IN',
    'include': 'INCLUDE',
    'int8': 'INT8',
    'int16': 'INT16',
    'int32': 'INT32',
    'int8be': 'INT8BE',
    'int16be': 'INT16BE',
    'int32be': 'INT32BE',
    'matches': 'MATCHES',
    'nocase': 'NOCASE',
    'not': 'NOT',
    'of': 'OF',
    'or': 'OR',
    'private': 'PRIVATE',
    'rule': 'RULE',
    'them': 'THEM',
    'true': 'TRUE',
    'wide': 'WIDE',
    'uint8': 'UINT8',
    'uint16': 'UINT16',
    'uint32': 'UINT32',
    'uint8be': 'UINT8BE',
    'uint16be': 'UINT16BE',
    'uint32be': 'UINT32BE',
}

tokens = tokens + list(reserved.values())

# Regular expression rules for simple tokens
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_EQUIVALENT = r'=='
t_NEQUALS = r'!='
t_EQUALS = r'='
t_LBRACE = r'{'
t_RBRACE = r'}'
t_PLUS = r'\+'
t_PIPE = r'\|'
t_BACKSLASH = r'\\'
t_FORWARDSLASH = r'/'
t_COMMA = r','
t_GREATERTHAN = r'>'
t_LESSTHAN = r'<'
t_GREATEREQUAL = r'>='
t_LESSEQUAL = r'<='
t_PERIOD = r'\.'
t_COLON = r':'
t_STAR = r'\*'
t_LBRACK = r'\['
t_RBRACK = r'\]'
t_HYPHEN = r'\-'
t_AMPERSAND = r'&'
t_DOTDOT = r'\.\.'


def t_COMMENT(t):
    r'(//.*)(?=\n)'
    pass
    # No return value. Token discarded


# http://comments.gmane.org/gmane.comp.python.ply/134
def t_MCOMMENT(t):
    # r'/\*(.|\n)*?\*/'
    r'/\*(.|\n|\r|\r\n)*?\*/'
    if '\r\n' in t.value:
        t.lineno += t.value.count('\r\n')
    else:
        t.lineno += t.value.count('\n')
    pass


# Define a rule so we can track line numbers
def t_NEWLINE(t):
    # r'\n+'
    r'(\n|\r|\r\n)+'
    t.lexer.lineno += len(t.value)
    t.value = t.value
    pass


def t_HEXNUM(t):
    r'0x[A-Fa-f0-9]+'
    t.value = t.value
    return t


def t_SECTIONMETA(t):
    r'meta:'
    t.value = t.value
    return t


def t_SECTIONSTRINGS(t):
    r'strings:'
    t.value = t.value
    return t


def t_SECTIONCONDITION(t):
    r'condition:'
    t.value = t.value
    return t


def t_STRING(t):
    # r'".+?"(?<![^\\]\\")'
    r'".*?"(?<![^\\]\\")(?<![^\\][\\]{3}")(?<![^\\][\\]{5}")'
    t.value = t.value
    return t


def t_BYTESTRING(t):
    r'\{[\|\(\)\[\]\-\?a-fA-f0-9\s]+\}'
    t.value = t.value
    return t


def t_REXSTRING(t):
    r'\/.+\/(?=\s|$)'
    t.value = t.value
    return t


def t_STRINGNAME(t):
    r'\$[0-9a-zA-Z\-_*]*'
    t.value = t.value
    return t


def t_STRINGNAME_ARRAY(t):
    r'@[0-9a-zA-Z\-_*]*'
    t.value = t.value
    return t


def t_NUM(t):
    r'\d+(\.\d+)?|0x\d+'
    t.value = t.value
    return t


def t_ID(t):
    r'[a-zA-Z_]{1}[a-zA-Z_0-9.]*'
    t.type = reserved.get(t.value, 'ID')  # Check for reserved words
    return t


def t_STRINGCOUNT(t):
    r'\#[^\s]*'
    t.value = t.value
    return t

# A string containing ignored characters (spaces and tabs)
# t_ignore = ' \t\r\n'
t_ignore = ' \t'


# Error handling rule
def t_error(t):
    raise TypeError('Illegal character {} at line {}'.format(t.value[0], str(t.lexer.lineno)))
    t.lexer.skip(1)

precedence = (('right', 'NUM'), ('right', 'ID'), ('right', 'HEXNUM'))

lexer = lex.lex(debug=False)

########################################################################################################################
# PARSER
########################################################################################################################


def p_rules(p):
    '''rules : rules rule
             | rule'''


def p_rule(p):
    '''rule : imports_and_scopes RULE ID tag_section LBRACE rule_body RBRACE'''

    logger.debug('Matched rule: {}'.format(str(p[3])))
    parserInterpreter.addElement(ElementTypes.RULE_NAME, str(p[3]))


def p_imports_and_scopes(p):
    '''imports_and_scopes : imports
                          | includes
                          | scopes
                          | imports scopes
                          | includes scopes
                          | '''


def p_imports(p):
    '''imports : imports import
               | includes
               | import'''


def p_includes(p):
    '''includes : includes include
                | imports
                | include'''


def p_import(p):
    'import : IMPORT STRING'
    logger.debug('Matched import: {}'.format(p[2]))
    parserInterpreter.addElement(ElementTypes.IMPORT, p[2])


def p_include(p):
    'include : INCLUDE STRING'
    logger.debug('Matched include: {}'.format(p[2]))
    parserInterpreter.addElement(ElementTypes.INCLUDE, p[2])


def p_scopes(p):
    '''scopes : scopes scope
              | scope'''


def p_tag_section(p):
    '''tag_section : COLON tags
                   | '''


def p_tags(p):
    '''tags : tags tag
            | tag'''


def p_tag(p):
    'tag : ID'
    logger.debug('Matched tag: {}'.format(str(p[1])))
    parserInterpreter.addElement(ElementTypes.TAG, p[1])


def p_scope(p):
    '''scope : PRIVATE
             | GLOBAL'''
    logger.debug('Matched scope identifier: {}'.format(str(p[1])))
    parserInterpreter.addElement(ElementTypes.SCOPE, p[1])


def p_rule_body(p):
    'rule_body : sections'
    logger.debug('Matched rule body')


def p_rule_sections(p):
    '''sections : sections section
                | section'''


def p_rule_section(p):
    '''section : meta_section
               | strings_section
               | condition_section'''


def p_meta_section(p):
    'meta_section : SECTIONMETA meta_kvs'
    logger.debug('Matched meta section')


def p_strings_section(p):
    'strings_section : SECTIONSTRINGS strings_kvs'


def p_condition_section(p):
    '''condition_section : SECTIONCONDITION expression'''


# Meta elements.
def p_meta_kvs(p):
    '''meta_kvs : meta_kvs meta_kv
                | meta_kv'''
    logger.debug('Matched meta kvs')


def p_meta_kv(p):
    '''meta_kv : ID EQUALS STRING
               | ID EQUALS ID
               | ID EQUALS TRUE
               | ID EQUALS FALSE
               | ID EQUALS NUM'''
    key = str(p[1])
    value = str(p[3])
    logger.debug('Matched meta kv: {} equals {}'.format(key, value))
    parserInterpreter.addElement(ElementTypes.METADATA_KEY_VALUE, MetaElement(key, value, ))


# Strings elements.
def p_strings_kvs(p):
    '''strings_kvs : strings_kvs strings_kv
                   | strings_kv'''
    logger.debug('Matched strings kvs')


def p_strings_kv(p):
    '''strings_kv : STRINGNAME EQUALS STRING
                  | STRINGNAME EQUALS STRING string_modifiers
                  | STRINGNAME EQUALS BYTESTRING
                  | STRINGNAME EQUALS REXSTRING
                  | STRINGNAME EQUALS REXSTRING string_modifiers'''

    key = str(p[1])
    value = str(p[3])
    logger.debug('Matched strings kv: {} equals {}'.format(key, value))
    parserInterpreter.addElement(ElementTypes.STRINGS_KEY_VALUE, StringsElement(key, value, ))


def p_string_modifers(p):
    '''string_modifiers : string_modifiers string_modifier
                        | string_modifier'''


def p_string_modifier(p):
    '''string_modifier : NOCASE
                       | ASCII
                       | WIDE
                       | FULLWORD'''
    logger.debug('Matched a string modifier: {}'.format(p[1]))
    parserInterpreter.addElement(ElementTypes.STRINGS_MODIFIER, p[1])


# Condition elements.
def p_expression(p):
    '''expression : expression term
                  | term'''


def p_condition(p):
    '''term : ID
            | STRING
            | NUM
            | HEXNUM
            | LPAREN
            | RPAREN
            | LBRACK
            | RBRACK
            | DOTDOT
            | EQUIVALENT
            | EQUALS
            | NEQUALS
            | PLUS
            | PIPE
            | BACKSLASH
            | FORWARDSLASH
            | COMMA
            | GREATERTHAN
            | LESSTHAN
            | GREATEREQUAL
            | LESSEQUAL
            | PERIOD
            | COLON
            | STAR
            | HYPHEN
            | AMPERSAND
            | ALL
            | AND
            | ANY
            | AT
            | CONTAINS
            | ENTRYPOINT
            | FALSE
            | FILESIZE
            | FOR
            | IN
            | INT8
            | INT16
            | INT32
            | INT8BE
            | INT16BE
            | INT32BE
            | MATCHES
            | NOT
            | OR
            | OF
            | THEM
            | TRUE
            | UINT8
            | UINT16
            | UINT32
            | UINT8BE
            | UINT16BE
            | UINT32BE
            | STRINGNAME
            | STRINGNAME_ARRAY
            | STRINGCOUNT'''

    logger.debug('Matched a term: {}'.format(p[1]))
    parserInterpreter.addElement(ElementTypes.TERM, p[1])


# Error rule for syntax errors
def p_error(p):
    raise TypeError('Unknown text at {} ; token of type {}'.format(p.value, p.type))

parser = yacc.yacc(debug=False)
