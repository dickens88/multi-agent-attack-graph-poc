---
name: investigation-termination-protocol
description: Load this skill during attack tracing iterations to determine whether 
  investigation should continue or stop. Must be consulted at the end of every 
  tracing iteration before deciding next steps. Contains authoritative termination 
  conditions that override agent judgment.
allowed-tools: read_file
---

# Investigation Termination Protocol

## Overview

This skill defines the exact conditions under which attack tracing stops.
It is authoritative — agent judgment must defer to these rules.

## When to load

- At the end of EVERY iteration inside tracer-agent
- Before making any "continue vs stop" decision
- When frontier nodes appear exhausted

## Instructions

### Step 1: Load termination rules
Use read_file to load: `skills/investigation-protocol/termination_rules.md`

### Step 2: Evaluate current state against each rule (in order)

Check STOP conditions top-to-bottom. Stop evaluation at first match.

### Step 3: Record decision in structured format

Output your termination evaluation as JSON before proceeding.
