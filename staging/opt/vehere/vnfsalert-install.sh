#!/bin/bash

cd vnfsui

tar xaf vnfsalert-0.1.31.tar.gz

cd vnfsalert-0.1.31

pip install "setuptools>=11.3"

pip install -r requirements.txt --use-wheel --no-index --find-links wheelhouse

sudo python setup.py install

cd ..


