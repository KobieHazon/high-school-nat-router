
"""
##################################################################
# Created By: Kobie Hazon                                        #
# Date: 04/05/2017                                               #
# Name: LoggingSystem                                            #
# Version: 1.0                                                   #
# Linux Tested Versions: Centos 7 64 bit                         #
# Python Tested Versions: 2.7.10 32-bit                          #
# Python Environment  : PyCharm 2017.1.1                         #
##################################################################
"""

import logging
import os
import sys
import datetime
from optparse import OptionParser


class LoggingManager:

    def __init__(self):

        self.loglevel = self.logging_by_option()

    def option_parsing(self):
        parser = OptionParser()
        parser.add_option("-l", "--log", dest="loglevel",
                          help="Write logging information according to the selected level")
        parser.add_option("-q", "--quiet",
                          action="store_false", dest="verbose", default=True,
                          help="don't print status messages to stdout")

        self.options, args = parser.parse_args()
        option_dict = vars(self.options)

        if not option_dict['verbose']:
            f = open(os.devnull, 'w')
            sys.stdout = f

        return option_dict

    def logging_by_option(self):
        self.options = self.option_parsing()
        if self.options['loglevel'] is not None:
            numeric_level = getattr(logging, self.options['loglevel'].upper(), None)
            if not isinstance(numeric_level, int):
                raise ValueError('Invalid log level: %s' % self.options['loglevel'])

            if self.options['loglevel'] == 'debug' or self.options['loglevel'] == 'debug'.upper():
                self.options['loglevel'] = 'DEBUG'
                logging.basicConfig(filename=(self.options['loglevel'] + '.log'), level=logging.DEBUG,
                                    format='%(levelname)s: %(message)s')
                logging.debug('### ' + str(datetime.datetime.now()) + " ###")
                logging.basicConfig(filename=(self.options['loglevel'] + '.log'), level=logging.DEBUG,
                                    format='%(asctime)s %(message)s: ', datefmt='%m/%d/%Y %I:%M:%S %p')
                log = open("DEBUG.log", "a")
                sys.stdout = log

            elif self.options['loglevel'] == 'error' or self.options['loglevel'] == 'error'.upper():
                self.options['loglevel'] = 'ERROR'
                logging.basicConfig(filename=(self.options['loglevel'] + '.log'), level=logging.ERROR,
                                    format='%(levelname)s: %(message)s')
                logging.error('### ' + datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p") + " ###")
                logging.basicConfig(filename=(self.options['loglevel'] + '.log'), level=logging.ERROR,
                                    format='%(asctime)s %(message)s: ', datefmt='%m/%d/%Y %I:%M:%S %p')

            elif self.options['loglevel'] == 'info' or self.options['loglevel'] == 'info'.upper():
                self.options['loglevel'] = 'INFO'
                logging.basicConfig(filename=(self.options['loglevel'] + '.log'), level=logging.INFO,
                                    format='%(levelname)s: %(message)s')
                logging.info('### ' + datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p") + " ###")
                logging.basicConfig(filename=(self.options['loglevel'] + '.log'), level=logging.INFO,
                                    format='%(asctime)s %(message)s: ', datefmt='%m/%d/%Y %I:%M:%S %p')
                log = open("INFO.log", "a")
                sys.stdout = log

            return self.options['loglevel']
