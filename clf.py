#!/usr/bin/env python3

'Ad-hoc analysis of web server log files in Combined Log Format.'

from datetime import datetime
import re, sys


USAGE = '''Usage:
    %s operator field [operator field]...

    Purpose: %s
    Operators:
'''


class LogLine:
    'A parsed line from an httpd access log in Combined Log File Format'

    # Regular expression for Common Log Format
    COMMON_LOG_FORMAT = re.compile(
        r'^(?P<host>[\d\.:a-f]+)\s' # IPv4 or IPv6
        r'(?P<identity>\S*)\s'
        r'(?P<user>\S*)\s'
        r'\[(?P<date>.*?)\]\s'
        r'"(?P<request>[^"]*)"\s'
        r'(?P<status>\d+)\s'
        r'(?P<bytes>\S*)\s'
        r'"(?P<referer>[^"]*)"\s' # [SIC]
        r'"(?P<user_agent>[^"]*)"\s', re.UNICODE)
        
    SEARCH_FIELDS = tuple( COMMON_LOG_FORMAT.groupindex.keys()) + (
        'method', 'uri', 'protocol', 'utcoffset')

    TIME_FORMAT = r'%d/%b/%Y:%H:%M:%S' # no %z for strptime


    # Defaults for illegal requests, e.g. SSL on port 80
    method   = None
    uri      = ''
    protocol = None


    def __init__( self, line):
        'Parse a common log file line'

        match = self.COMMON_LOG_FORMAT.match( line)
        if not match:
            raise ValueError( 'Not in CLF format: %s' % line)
        self.__dict__ = match.groupdict()

        self.status = int( self.status)
        self.bytes  = -1 if self.bytes == '-' else int( self.bytes)

        # Parse CLF timestamp into a naive datetime
        # Keep the UTC offset for timezone conversion.
        self.utcoffset = self.date[21:26]
        self.date = datetime.strptime( self.date[:20], self.TIME_FORMAT)

        # Break up the request
        parts = self.request.split()
        if len( parts) == 3:
            self.method, self.uri, self.protocol = parts


    @classmethod
    def usage( cls):
        print( 'Available fields: %s' % ', '.join( cls.SEARCH_FIELDS), file=sys.stderr)
        sys.exit( 1)


    def __str__( self):
        'Reconstruct CLF line from instance'

        args = self.__dict__.copy()
        args['date'] = self.date.strftime( self.TIME_FORMAT)
        return ( '%(host)s %(identity)s %(user)s '
                 '[%(date)s %(utcoffset)s] '
                 '"%(request)s" %(status)d %(bytes)d '
                 '"%(referer)s" "%(user_agent)s"') % args


class LogReader:
    
    def __init__( self, input):
        self.input = input
        self.errors = 0

    def __iter__( self):
        for line in self.input:
            try: yield LogLine( line)
            except ValueError as e:
                print( e)
                self.errors += 1
                print( line)


class Op:
    'Operations base class'
    
    fields = None
    
    def __init__( self, field):
        self.field = field
    
    @property
    def field_name( self):
        return self.field.replace( '_', ' ').capitalize()
        
    def add( self, line):
        if not self.fields:
            self.fields = ', '.join( line.__dict__.keys())
            if not hasattr( line, self.field): LogLine.usage()
        return self.update( getattr( line, self.field))
        
    def __str__( self):
        return '%s( %s)' % (self.__name__.lower(), self.field)

    def values( self): return []
    

##### Filters and counters #####

class Count( Op):
    'Count lines, grouped by field'
    
    counters = {}

    def update( self, f):
        if f not in self.counters: self.counters[f] = 0
        self.counters[f] += 1

    def values( self):
        yield '     Count %s' % self.field_name
        yield '---------- ' + ('-' * len( self.field))
        for r in sorted( ((v, k) for k, v in self.counters.items()), reverse=True):
            yield '%10d %s' % r


class Set( Count):
    'Extract unique field values'
    
    def values( self):
        return sorted( self.counters.keys())


class Max( Op):
    'Find the maximum field value'
    
    result = None

    def update( self, f):
        if self.result is None or f > self.result:
            self.result = f


class Min( Op):
    'Find the minimum field value'
    
    result = None

    def update( self, f):
        if self.result is None or f < self.result:
            self.result = f


##### Arithmetic aggregations #####

class Sum( Op):
    'Add numeric field values'
    
    counters = {}

    def update( self, f):
        f = int( f)
        if f not in self.counters: self.counters[f] = 0
        self.counters[f] += 1
        
    @property
    def result( self):
        return sum( v * n for v, n in self.counters.items())


class Avg( Sum):
    'Compute the average of a numeric field'
    
    @property
    def result( self):
        return super().result / sum( self.counters.values())


##### Command line interface #####

if __name__ == '__main__':

    actions = []
    _ops = (Count, Set, Avg, Max, Min, Sum)
    options = dict( (op.__name__.lower(), op) for op in _ops)
    
    def usage():
        print( USAGE % (sys.argv[0], __doc__), file=sys.stderr)
        for op in _ops:
            print( '\t%s:\t%s' % (op.__name__.lower(), op.__doc__))
        print( file=sys.stderr)
        LogLine.usage()
    
    pos = 1    
    while sys.argv[pos:]:
        op = sys.argv[pos]
        pos += 1
        if op in options:
            actions.append( options[op]( sys.argv[pos]))
            pos += 1
        else: usage()
        
    if not actions: usage()

    reader = LogReader( sys.stdin)
    try:
        for line in reader:
            for a in actions: a.add( line)
    except KeyboardInterrupt:
        sys.exit( 0)
    
    # Dump the result
    for a in actions:
        if hasattr( a, 'result'):
            print( '%s = %s' % (a.__class__.__name__, a.result))
        else:
            for v in a.values(): print( v)
    if reader.errors:
        print( '# Errors:', reader.errors)
        