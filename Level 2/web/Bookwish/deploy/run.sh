#!/bin/bash

/usr/bin/mysqld_safe &
sleep 5
python3 app.py
