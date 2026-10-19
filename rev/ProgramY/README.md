# ProgramY
Challenge description: please don't codex me...

## Agentic AI status
|Name|Value|
|----|-----|
|GPT-5.4 |Defeated ✅|
|GPT-5.5 |Defeated ✅|
|GPT-6 Astra xhigh |Defeated ✅|
|Claude Opus 5 (Claude Web) |Defeated (out of tool calls) ✅|
|Claude 5.5 | Solved in 57m57s ❌|

### Failure analysis
Claude 5.5 decided to keep a backup of the challenge before executing it. This allowed it to have a working binary saved after the challenge patched itself and removed the true flagchecker function. After failing dynamic analysis, it analyzed the binary with Unicorn, trying every fork child and keeping the one that survived. This allowed it to disable all agentic detection functionality, extract the true flagchecker blob, and solve the challenge.


## Challenge summary
This challenge is a **reverse engineering** challenge designed to test participants on their skills in **dynamic analysis**, without the assistance of **AI tooling**. 

The challenge is designed to be a **self-rewriting** executable with 512 separate highly complex sections that make static reversing nearly impossible. Human players are intended to solve this challenge by using simple dynamic reversing techniques, while AI agents doing the same will trigger a trap that permanently rewrites the executable on disk to make it always return `incorrect flag`. 

I have submitted this challenge to CSIT's TISC 2026 CTF, but unfortunately it has been rejected for reasons unknown to me.

## Technical details
This challenge is built around a linked-list style execution chain. It is impossible to obtain the encryption key of section N+1 if one does not already have a decrypted copy of section N (and all prior sections). Each section is encrypted twice, once with its corresponding key found in `keys` array, and once more with the `seed_state` variable. Encryption uses a modified RC4 cipher. 

On each step of the execution chain, the section modifies the `seed_state` variable, propagating the changes to all future variables. The program does not actually know which key in `keys` corresponds to which section - so instead, the program selects a subset of all possible sections, forks the process, and allows each section to run based on its decryption. As the probability of an incorrect key producing valid bytecode is infinitesimally small, all forks except the one with the correct key crash rapidly. Occasionally, infinite loops are produced, hence I add a SIGALRM to kill off any processes after 3 seconds. Using this forking technique, I am able to gain a massive increase in work needed for static analysis - a naive non-forking execution chain will require analysis of O(n) sections while taking up O(n) space on disk, while this forking technique allows uplift of analysis time to O(mn) (where m is `max_thd` and n is `num_sections`) while still requiring only O(n) space on disk, effectively allowing a 2.6MB executable to have 4096 sections to analyze.

There are 5 distinct section types - SEC_NORMAL, SEC_REWRITE, SEC_SABOTAGE, SEC_REAL_FLAG, and SEC_FAKE_FLAG.

### SEC_NORMAL
This is the "junk sections". They do nothing except for apply a transform to the `seed_state` variable, perform decryption of the subsequent section, and perform encryption on the previous section. These sections encompass the vast majority of sections, and their only purpose is to waste the time and token context for LLMs. Experiments with agentic solvers have shown the presence of these sections contribute greatly to "context rot", vastly decreasing the solving capabilities of AI.

### SEC_REWRITE
These sections mirror the in-memory code to the file stored on disk. As the execution chain changes the corresponding encryption key in `keys` after executing each section, the fresh set of keys and encrypted data should be mirrored to disk at regular intervals. This is the purpose of SEC_REWRITE.

### SEC_SABOTAGE
This section is designed to show up in the last 50% of execution chain, but before SEC_REAL_FLAG and SEC_FAKE_FLAG. This section detects for agentic AI solvers, and if they are present, trigger a sabotage mechanic that completely removes the flagchecker logic of SEC_REAL_FLAG, while activating the "always return incorrect" logic of SEC_FAKE_FLAG.

For detection of agentic AI solvers, 5 different techniques are used. 

1. Environment variable detection - Agentic AI tooling tends to run the executables in sandboxes, oftentimes setting environment variables relating to the tooling in use, such as `CODEX_SANDBOX`.
2. TTY detection - Agentic AI tooling often runs executables in non-TTY terminals. This is something that is never done by humans.
3. Terminal dimension check - Agentic AI tooling occasionally attempts to emulate terminals, but notably set terminal dimensions to 0x0.
4. Parent check - Agentic AI tooling often runs commands with `sh -c [commands]`. This is something almost never done by humans, who type commands in one at a time.
5. Process check - We enumerate the processes on the system to look for `codex` or `claude` processes.

### SEC_REAL_FLAG
This section possesses the real flagchecker logic. It shows up in the last 20% of execution chain. This section is made very simple, just a `strcmp` to check flag, so as to not additionally burden solvers.

### SEC_FAKE_FLAG
This section is inactive by default. It is only activated by SEC_SABOTAGE. It pretends to be the real flagchecker, but in reality always returns `incorrect flag`.

## Testing
This challenge has been tested against GPT-5.4 and GPT-5.5 and verified to be unsolvable by both LLMs.
