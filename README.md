# Ｑuark APK Lab

A Apk Library for the improvement of the five-stage inspection of Quark.

## The ideal of APK Lab

According to #52, using androguard may cause potential issues with Quark. There were concerns about it in the past:

+ The maintaining of androguard.
+ Need to rely on `pip install androguard` from Github.
+ Quark only uses the decompile function of androguard.

Thus, here comes Radare2. A portable tool provides a set of libraries and tools to work with binary files !

In this lab, I would be using features from radare2 to achieve the five-stage inspection of Quark. With aids of r2pipe, all apk-related information gathering will be done by radare2 commands only !

## Goals of the Lab

 - Read app permissions from `Manifest`
 - Get native APIs which the app uses
 - Get combinations of native APIs
 - Get sequences of native APIs

