# Encrypted Firefox portable profile

*Protects your data on-the-go*

## What is this?

This script allows you to setup a password for your [Firefox Portable](https://portableapps.com/apps/internet/firefox_portable) by encrypting personal files, so you can travel with your profile on USB stick and do not worry about thieves.

## How does this work?

During first run you will be asked to enter your password.

This password is used to encrypt generated RSA keys which are used to encrypt your personal files using AES with random password.

## Usage

Download latest binaries from [releases](https://github.com/esoadamo/EncryptedFFPorable/releases) and put them into portable Firefox's folder (together with FirefoxPortable.exe)

Run `encrypted_profile.exe` and follow instructions.

You may use also your unencrypted profile along, both profiles use different files.