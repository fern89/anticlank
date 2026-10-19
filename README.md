# anticlank
In recent CTFs, challenges have become increasingly frustrating to human players as teams with little to no cybersecurity background make liberal use of AI agents to rapidly solve challenges.

In this repository, I have placed some proofs of concept involving challenges I have written that are aware of agentic AI solvers, and attempt to fight back.

The challenges shown must obey these rules:
1. The AI should not realize this challenge was specifically designed to thwart it
2. A decently skilled human CTF player should reasonably be able to solve the challenge in <2h​
3. It should be unsolvable by AI, or give the AI a different flag
4. It should not attempt to attack or modify the agentic runtime in any form (no deletion of agentic binaries, killing of agentic processes, etc.)
5. It should not use any prompting-based attacks (no prompt engineering, prompt injection, magic refusal strings, etc.)
