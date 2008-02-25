"""
Certmaster

Copyright 2007-2008, Red Hat, Inc
See AUTHORS

This software may be freely redistributed under the terms of the GNU
general public license.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
"""

import exceptions


class CertMasterException(exceptions.Exception):
    pass

class CMException(CertMasterException):
    pass

class InvalidMethodException(CertMasterException):
    pass

# FIXME: more sub-exceptions maybe

