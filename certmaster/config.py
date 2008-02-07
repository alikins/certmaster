# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# Copyright 2002 Duke University 
# filched from yum  - menno smits wrote this - he rocks


import os
import sys
import warnings
import copy
import urlparse
from ConfigParser import NoSectionError, NoOptionError, ConfigParser
from ConfigParser import ParsingError
import exceptions

CONFIG_FILE = "/etc/certmaster/certmaster.conf"

class ConfigError(exceptions.Exception):
    def __init__(self, value=None):
        exceptions.Exception.__init__(self)
        self.value = value
    def __str__(self):
        return "%s" %(self.value,)
 
   
class Option(object):
    '''
    This class handles a single Yum configuration file option. Create
    subclasses for each type of supported configuration option.
    
    Python descriptor foo (__get__ and __set__) is used to make option
    definition easy and consise.
    '''

    def __init__(self, default=None):
        self._setattrname()
        self.inherit = False
        self.default = default

    def _setattrname(self):
        '''Calculate the internal attribute name used to store option state in
        configuration instances.
        '''
        self._attrname = '__opt%d' % id(self)

    def __get__(self, obj, objtype):
        '''Called when the option is read (via the descriptor protocol). 

        @param obj: The configuration instance to modify.
        @param objtype: The type of the config instance (not used).
        @return: The parsed option value or the default value if the value
            wasn't set in the configuration file.
        '''
        if obj is None:
            return self

        return getattr(obj, self._attrname, None)

    def __set__(self, obj, value):
        '''Called when the option is set (via the descriptor protocol). 

        @param obj: The configuration instance to modify.
        @param value: The value to set the option to.
        @return: Nothing.
        '''
        # Only try to parse if its a string
        if isinstance(value, basestring):
            try:
                value = self.parse(value)
            except ValueError, e:
                # Add the field name onto the error
                raise ValueError('Error parsing %r: %s' % (value, str(e)))

        setattr(obj, self._attrname, value)

    def setup(self, obj, name):
        '''Initialise the option for a config instance. 
        This must be called before the option can be set or retrieved. 

        @param obj: BaseConfig (or subclass) instance.
        @param name: Name of the option.
        '''
        setattr(obj, self._attrname, copy.copy(self.default))

    def clone(self):
        '''Return a safe copy of this Option instance
        '''
        new = copy.copy(self)
        new._setattrname()
        return new

    def parse(self, s):
        '''Parse the string value to the Option's native value.

        @param s: Raw string value to parse.
        @return: Validated native value.
    
        Will raise ValueError if there was a problem parsing the string.
        Subclasses should override this.
        '''
        return s

    def tostring(self, value):
        '''Convert the Option's native value to a string value.

        @param value: Native option value.
        @return: String representation of input.

        This does the opposite of the parse() method above.
        Subclasses should override this.
        '''
        return str(value)


def Inherit(option_obj):
    '''Clone an Option instance for the purposes of inheritance. The returned
    instance has all the same properties as the input Option and shares items
    such as the default value. Use this to avoid redefinition of reused
    options.

    @param option_obj: Option instance to inherit.
    @return: New Option instance inherited from the input.
    '''
    new_option = option_obj.clone()
    new_option.inherit = True
    return new_option


class ListOption(Option):

    def __init__(self, default=None):
        if default is None:
            default = []
        super(ListOption, self).__init__(default)

    def parse(self, s):
        """Converts a string from the config file to a workable list

        Commas and spaces are used as separators for the list
        """
        # we need to allow for the '\n[whitespace]' continuation - easier
        # to sub the \n with a space and then read the lines
        s = s.replace('\n', ' ')
        s = s.replace(',', ' ')
        return s.split()

    def tostring(self, value):
        return '\n '.join(value)


class UrlOption(Option):
    '''
    This option handles lists of URLs with validation of the URL scheme.
    '''

    def __init__(self, default=None, schemes=('http', 'ftp', 'file', 'https'), 
            allow_none=False):
        super(UrlOption, self).__init__(default)
        self.schemes = schemes
        self.allow_none = allow_none

    def parse(self, url):
        url = url.strip()

        # Handle the "_none_" special case
        if url.lower() == '_none_':
            if self.allow_none:
                return None
            else:
                raise ValueError('"_none_" is not a valid value')

        # Check that scheme is valid
        (s,b,p,q,f,o) = urlparse.urlparse(url)
        if s not in self.schemes:
            raise ValueError('URL must be %s not "%s"' % (self._schemelist(), s))

        return url

    def _schemelist(self):
        '''Return a user friendly list of the allowed schemes
        '''
        if len(self.schemes) < 1:
            return 'empty'
        elif len(self.schemes) == 1:
            return self.schemes[0]
        else:
            return '%s or %s' % (', '.join(self.schemes[:-1]), self.schemes[-1])


class UrlListOption(ListOption):
    '''
    Option for handling lists of URLs with validation of the URL scheme.
    '''

    def __init__(self, default=None, schemes=('http', 'ftp', 'file', 'https')):
        super(UrlListOption, self).__init__(default)

        # Hold a UrlOption instance to assist with parsing
        self._urloption = UrlOption(schemes=schemes)
        
    def parse(self, s):
        out = []
        for url in super(UrlListOption, self).parse(s):
            out.append(self._urloption.parse(url))
        return out


class IntOption(Option):
    def parse(self, s):
        try:
            return int(s)
        except (ValueError, TypeError), e:
            raise ValueError('invalid integer value')


class BoolOption(Option):
    def parse(self, s):
        s = s.lower()
        if s in ('0', 'no', 'false'):
            return False
        elif s in ('1', 'yes', 'true'):
            return True
        else:
            raise ValueError('invalid boolean value')

    def tostring(self, value):
        if value:
            return "1"
        else:
            return "0"


class FloatOption(Option):
    def parse(self, s):
        try:
            return float(s.strip())
        except (ValueError, TypeError):
            raise ValueError('invalid float value')


class SelectionOption(Option):
    '''Handles string values where only specific values are allowed
    '''
    def __init__(self, default=None, allowed=()):
        super(SelectionOption, self).__init__(default)
        self._allowed = allowed
        
    def parse(self, s):
        if s not in self._allowed:
            raise ValueError('"%s" is not an allowed value' % s)
        return s

class BytesOption(Option):

    # Multipliers for unit symbols
    MULTS = {
        'k': 1024,
        'm': 1024*1024,
        'g': 1024*1024*1024,
    }

    def parse(self, s):
        """Parse a friendly bandwidth option to bytes

        The input should be a string containing a (possibly floating point)
        number followed by an optional single character unit. Valid units are
        'k', 'M', 'G'. Case is ignored.
       
        Valid inputs: 100, 123M, 45.6k, 12.4G, 100K, 786.3, 0
        Invalid inputs: -10, -0.1, 45.6L, 123Mb

        Return value will always be an integer

        1k = 1024 bytes.

        ValueError will be raised if the option couldn't be parsed.
        """
        if len(s) < 1:
            raise ValueError("no value specified")

        if s[-1].isalpha():
            n = s[:-1]
            unit = s[-1].lower()
            mult = self.MULTS.get(unit, None)
            if not mult:
                raise ValueError("unknown unit '%s'" % unit)
        else:
            n = s
            mult = 1
             
        try:
            n = float(n)
        except ValueError:
            raise ValueError("couldn't convert '%s' to number" % n)

        if n < 0:
            raise ValueError("bytes value may not be negative")

        return int(n * mult)


class ThrottleOption(BytesOption):

    def parse(self, s):
        """Get a throttle option. 

        Input may either be a percentage or a "friendly bandwidth value" as
        accepted by the BytesOption.

        Valid inputs: 100, 50%, 80.5%, 123M, 45.6k, 12.4G, 100K, 786.0, 0
        Invalid inputs: 100.1%, -4%, -500

        Return value will be a int if a bandwidth value was specified or a
        float if a percentage was given.

        ValueError will be raised if input couldn't be parsed.
        """
        if len(s) < 1:
            raise ValueError("no value specified")

        if s[-1] == '%':
            n = s[:-1]
            try:
                n = float(n)
            except ValueError:
                raise ValueError("couldn't convert '%s' to number" % n)
            if n < 0 or n > 100:
                raise ValueError("percentage is out of range")
            return n / 100.0
        else:
            return BytesOption.parse(self, s)


class BaseConfig(object):
    '''
    Base class for storing configuration definitions. Subclass when creating
    your own definitons.
    '''

    def __init__(self):
        self._section = None

        for name in self.iterkeys():
            option = self.optionobj(name)
            option.setup(self, name)

    def __str__(self):
        out = []
        out.append('[%s]' % self._section)
        for name, value in self.iteritems():
            out.append('%s: %r' % (name, value))
        return '\n'.join(out)

    def populate(self, parser, section, parent=None):
        '''Set option values from a INI file section.

        @param parser: ConfParser instance (or subclass)
        @param section: INI file section to read use.
        @param parent: Optional parent BaseConfig (or subclass) instance to use
            when doing option value inheritance.
        '''
        self.cfg = parser
        self._section = section

        for name in self.iterkeys():
            option = self.optionobj(name)
            value = None
            try:
                value = parser.get(section, name)
            except (NoSectionError, NoOptionError):
                # No matching option in this section, try inheriting
                if parent and option.inherit:
                    value = getattr(parent, name)
               
            if value is not None:
                setattr(self, name, value)

    def optionobj(cls, name):
        '''Return the Option instance for the given name
        '''
        obj = getattr(cls, name, None)
        if isinstance(obj, Option):
            return obj
        else:
            raise KeyError
    optionobj = classmethod(optionobj)

    def isoption(cls, name):
        '''Return True if the given name refers to a defined option 
        '''
        try:
            cls.optionobj(name)
            return True
        except KeyError:
            return False
    isoption = classmethod(isoption)

    def iterkeys(self):
        '''Yield the names of all defined options in the instance.
        '''
        for name, item in self.iteritems():
            yield name

    def iteritems(self):
        '''Yield (name, value) pairs for every option in the instance.

        The value returned is the parsed, validated option value.
        '''
        # Use dir() so that we see inherited options too
        for name in dir(self):
            if self.isoption(name):
                yield (name, getattr(self, name))

    def write(self, fileobj, section=None, always=()):
        '''Write out the configuration to a file-like object

        @param fileobj: File-like object to write to
        @param section: Section name to use. If not-specified the section name
            used during parsing will be used.
        @param always: A sequence of option names to always write out.
            Options not listed here will only be written out if they are at
            non-default values. Set to None to dump out all options.
        '''
        # Write section heading
        if section is None:
            if self._section is None:
                raise ValueError("not populated, don't know section")
            section = self._section

        # Updated the ConfigParser with the changed values    
        cfgOptions = self.cfg.options(section)
        for name,value in self.iteritems():
            option = self.optionobj(name)
            if always is None or name in always or option.default != value or name in cfgOptions :
                self.cfg.set(section,name, option.tostring(value))
        # write the updated ConfigParser to the fileobj.
        self.cfg.write(fileobj)

    def getConfigOption(self, option, default=None):
        warnings.warn('getConfigOption() will go away in a future version of Yum.\n'
                'Please access option values as attributes or using getattr().',
                DeprecationWarning)
        if hasattr(self, option):
            return getattr(self, option)
        return default

    def setConfigOption(self, option, value):
        warnings.warn('setConfigOption() will go away in a future version of Yum.\n'
                'Please set option values as attributes or using setattr().',
                DeprecationWarning)
        if hasattr(self, option):
            setattr(self, option, value)
        else:
            raise ConfigError, 'No such option %s' % option


def read_config(config_file, BaseConfigDerived):
    confparser = ConfigParser()
    opts = BaseConfigDerived()
    if os.path.exists(config_file):
        try:
            confparser.read(config_file)
        except ParsingError, e:
            print >> sys.stderr, "Error reading config file: %s" % e
            sys.exit(1)
    opts.populate(confparser, 'main')
    return opts
