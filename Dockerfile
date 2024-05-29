#
# Copyright (C) 2023 ColorTokens Inc.
# By Venky Raju <venky.raju@colortokens.com>
#
# Decodes the wfpstate.xml file produced by the command
# netsh wfp show state

FROM ubuntu:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install --break-system-packages -r requirements.txt
RUN dpkg --purge python3-pip
COPY django-wfpdump .

EXPOSE 8000
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
