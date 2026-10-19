# anticlank
In recent CTFs, challenges have become increasingly frustrating to human players as teams with little to no cybersecurity background make liberal use of AI agents to rapidly solve challenges.

In this repository, I have placed some proofs of concept involving challenges I have written that are aware of agentic AI solvers, and attempt to fight back.

The challenges shown must obey these rules:
1. The AI should not realize this challenge was specifically designed to thwart it
2. A decently skilled human CTF player should reasonably be able to solve the challenge in <2h​
3. It should be unsolvable by AI, or give the AI a different flag
4. It should not attempt to attack or modify the agentic runtime in any form (no deletion of agentic binaries, killing of agentic processes, etc.)
5. It should not use any prompting-based attacks (no prompt engineering, prompt injection, magic refusal strings, etc.)

The key concept of the challenges is that they should detect an environment in which an agentic AI is being used, and modify themselves to either be unsolvable or return a different flag. This can be effectively used to silently and subtly differentiate AI from human players, and can be a good tool to help catch cheaters for CTFs that ban AI.

I will only upload challenges that have been successfully solved by a model (but it should have at least defeated a few past models to prove the technique has some merit) or challenges that have been published as part of a public CTF. This will prevent AI from learning novel techniques that have not yet been defeated by any frontier models.
