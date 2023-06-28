#!/bin/sh
# This is how I manually build the image on my M1 mac
docker buildx build --push --platform linux/amd64 --tag us.icr.io/sweeden/mds3server:amd64 -f Dockerfile .

