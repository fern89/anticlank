# Build instructions
To build, run `build.py`. Dependencies for build are python and GCC. A file called `chal` will be generated in the current directory. This is the file that should be distributed to players.

Flag can be changed easily by modifying the flag string in `chal.h`. It is currently set to `CTF{i_am_haxxor}`. You may also test the challenge on a system with codex running by setting the environment variable `FORCE_CODEX_BYPASS=1`

# Code structure
`main.c` contains the main logic for the challenge. Notably, this includes the 5 types of sections (SEC_NORMAL, SEC_SABOTAGE, SEC_REAL_FLAG, SEC_FAKE_FLAG, and SEC_REWRITE) and the logic used to transition between sections. It mainly contains higher level abstractions.

`utils.h` contains the utility functions. These are mainly helper functions to used to push in-memory changes to disk, along with some functions for encryption.

`codex.h` contains the codex detection logic.

`junk.h` contains 20 random junk functions. This file is fully AI generated.

`chal.h` contains the flagchecker logic.

`build.py` contains the logic for generation of the section execution cycle. This file when run generates a `generated.h` header which is then used to compile the final binary. 

More details on the logic of the code is presented in the `README.md` of the root directory.
