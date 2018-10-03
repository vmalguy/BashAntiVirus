# BashAntiVirus

## What?
A Bash script that will ask VirtusTotal (VT) for informations about your running process.

## Why?
Because I can.

## But, this is exactly what you should not do with VT
I know. 
That is why I implemented a local cache of VT replies.

## Any Risk?
Beside running --my arbitrary code on your computer, this script will send sha256 hashes of your running process to VT and *the whole file* if it has never been scanned by VT before.

## TODO
- add a switch to turn on explicitly file upload (privacy issue)
