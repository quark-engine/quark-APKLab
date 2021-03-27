# Ｑuark APK Lab (WIP)

[Quark-Engine](https://github.com/quark-engine/quark-engine) is a well-known open-source Android malware analysis engine written in python. It is based on [Androguard](https://github.com/androguard/androguard), an open-source project for analyzing Android files. However, Androguard is no longer maintained by its author. To ensure the health of Quark-Engine, we had decided to replace Androguard with Radare2, a trending, and open-source reverse engineering tool.

## Why we replace Androguard with Radare2

There are concerns:
+ The maintaining of androguard.
+ The memory usage of androguard.
+ Need to rely on `pip install androguard` from Github.
+ Quark only uses the decompile function of androguard.

Therefore, we decided to replace Androguard with Radare2, a trending and active open-source tool. Radare2 has a strong community to support the entire project, which brings lots of popular programming language porting. Besides, it provides almost all the features that Androguard has. It is suitable to take the place of Androguard. 

## Goal of this lab

In this lab, I would be using features from radare2 to achieve the key features of Quark-Engine. All apk-related information gathering will be done by Radare2 commands only !

## QuickStart
### Requirements
+ Python 3.9+
+ Radare2 4.3.1+
+ Pipenv

### Installation
```
git clone https://github.com/quark-engine/quark-APKLab.git
cd quark-APKLab
pipenv install
```

Use `cli.py` as an entry point of Quark. For example,
```
pipenv shell python3 cli.py --help
```

This commands shows what features it can provide.

```
Usage: cli.py [OPTIONS]

Options:
  -a, --apk FILE                 Apk File  [required]
  -r, --rule DIRECTORY           Json Rule
  -t, --thershold INTEGER RANGE  Filter for summarizing crimes
  -o, --output FILENAME          Report as a json file
  -s, --summary                  Summary report
  --help                         Show this message and exit.
```

A common usage

```
pipenv shell python3 -a [Path to APK] -r [Path to rule directory] -s
```
**Note**: Radare2-based Quark is still WIP!!
