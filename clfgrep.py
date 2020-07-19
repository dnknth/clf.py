#!/usr/bin/env python3

'Scan web server log files.'

from clf import LogLine, LogReader, Op
import re

USAGE = '''Usage:
    %s field operator value

    Purpose:     %s
    Operators:   = for exact matches, ~ for regular expressions.
    Prefix with: ! to negate, * for case insensitive search, in this order.
'''

class Filter( Op):
    'Scan a log file by field values'    
    
    def __init__( self, input, field, op, arg):
        self.input = LogReader( input)
        self.negate = '!' in op
        self.nocase = '*' in op
        self.regex  = '~' in op
        self.field, self.op, self.arg = field, op, arg
        
        if self.regex:
            flags = re.I if self.nocase else 0
            self.arg = re.compile( self.arg, re.UNICODE + flags)
        elif self.nocase:
            arg = arg.lower()

    def __str__( self):
        arg = self.arg.pattern if self.regex else self.arg
        return '# %s( %s %s %s)' % (self.name, self.field, self.op, arg)

    def update( self, f):
        s = str( f)
        p = (self.arg.search( s) if self.regex
             else s.lower() == self.arg if self.nocase
             else s == self.arg)
        return not p if self.negate else p
    
    def __iter__( self):
        for line in self.input:
            if self.add( line):
                yield line
        

##### Command line interface #####

if __name__ == '__main__':
    
    import sys
    
    ARGS  = re.compile( r'([a-z_]+)\s*(!?\*?[=~])\s*(.*)')

    def usage():
        print( USAGE % (sys.argv[0], __doc__), file=sys.stderr)
        LogLine.usage()
        
    # Scan log
    args = ' '.join( sys.argv[1:]).strip()
    m = ARGS.match( args)
    if not m: usage()

    scanner = Filter( sys.stdin, *m.groups())
    try:
        for line in scanner: print( line)
    except KeyboardInterrupt:
        sys.exit( 0)
        
    if scanner.input.errors:
        print( '# Errors:', scanner.input.errors)
        