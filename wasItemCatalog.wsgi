#!/usr/bin/python
import sys
sys.path.insert(0,"/var/www/apps/")

from __init__.py import app as application
application.secret_key = 'r4zP1NNiX6pIC2KhBF9P5uQD'
