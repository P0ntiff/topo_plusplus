#!/bin/bash

ebtables -P FORWARD DROP
ebtables -A FORWARD -p 0x88CC -j ACCEPT


