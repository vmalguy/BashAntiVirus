# BashAntiVirus

## What?
A Bash script that will ask VirtusTotal (VT) for informations about your running process.

## Why?
Because I can.

## But, this is exactly what you should not do with VT
I know. 
That is why I implemented a local cache of VT replies.

## Any Risk?
Beside running my arbitrary code on your computer, this script will send sha256 hashes of your running process to VT and *the whole file* if it has never been scanned by VT before.

## Prerequisites
A VT API key. (https://www.virustotal.com/#/join-us)

## how to run
chmod +x BashAntiVirus.sh
./BashAntiVirus.sh "YOUR_VT_API_KEY"
Detection : 103e9972afdbe01061291137705183ea5c91b3a6ba07c22a9c0a50d2eab97bcc /bin/dash #  scan_date: 2018-04-05 08:07:04  total: 59  positives: 10
Detection : a638521202d66116990a5d922b63fb8ea0c4b657dcd2a36c81d656708d05f0ce /sbin/init #  scan_date: 2018-04-05 08:42:03  total: 59  positives: 10
Detection : 312cca85591204b759f3ea172a11f7b249d3c0b30109cf3ef717c10f8faa009b /usr/bin/perl #  scan_date: 2018-01-31 23:48:36  total: 59  positives: 123

## Cool, So I dont need a antivirus anymore ? 
This script will only detect a low skill attacker but commercial antivirus are also easily bypassable, no? 
