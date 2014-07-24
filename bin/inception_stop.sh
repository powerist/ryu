#!/bin/bash

ps -ef | grep python | grep ryu | grep -v grep | awk '{print $2}' | xargs kill -9
