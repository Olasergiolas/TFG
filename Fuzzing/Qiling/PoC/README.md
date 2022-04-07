# Qiling binary emulation framework PoC

## Introduction
This is a proof of concept to exhibit Qiling's capabilities when emulating binaries. This example is comprised of a
file containing C source code that will be cross-compiled to ARM and then fuzzed using a Qiling script written in Python. This is an interesting example since it simulates the pressence of code that would make traditional fuzzing work at non acceptable speeds and solves it by fuzzing only the sections of code we are interested in.

## Usage
