# Combined Log File utilities

Here are some small ad-hoc analysis tools for web server access logs:

* `clf.py`: Log file parser and statistics
* `clfgrep.py`: Find log lines by arbitrary criteria

## Usage

### clf.py

    clf.py operator field [operator field]...

    Operators:

        count:	Count lines, grouped by field
        set:	Extract unique field values
        avg:	Compute the average of a numeric field
        max:	Find the maximum field value
        min:	Find the minimum field value
        sum:	Add numeric field values

    Available fields: host, identity, user, date, request, status, bytes, referer, user_agent, method, uri, protocol, utcoffset

### clfgrep.py

    clfgrep.py field operator value

        Purpose:     Scan web server log files.
        Operators:   = for exact matches, ~ for regular expressions.
        Prefix with: ! to negate, * for case insensitive search, in this order.
    
## Examples

* `clf.py` or `clfgrep.py`: Usage instructions

### clf.py

* `clf.py count method < access.log`: Count different HTTP request methods
* `clf.py count protocol < access.log`: Count all HTTP protocol versions
* `clf.py set user_agent < access.log`: List all user agent strings
* `clf.py avg bytes < access.log`: Compute the average response size

### clfgrep.py

* `clfgrep.py method\*=post < access.log`: Find all POST requests
* `clfgrep.py useragent\*~bot < access.log`: Find all requests where the user agent contains `bot` (case insensitive)
* `clfgrep.py status=404 < access.log`: Find dead links

### Combinations

* `clfgrep.py status=404 < access.log | clf.py count uri`: Get the number of broken links
* `clfgrep.py protocol=HTTP/1.0 < access.log | ./clf.py count user_agent`: Rank broken user agents
* `clfgrep.py user_agent\*~bot < access.log | clf.py count user_agent`: Rank search engine hits
