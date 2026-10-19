import random, os

def generate_header(filename="generated.h", total_sections=1024, margin = 100, max_thd = 8):
    mod_val = total_sections // max_thd
    # N is the number of normal sections (0 to 1022)
    # The last section (index 1023) is end_sec
    N = total_sections - 1
    
    # Calculate cycle boundary indices dynamically
    last_20_percent_start = int(total_sections * 0.8)
    last_50_percent_start = int(total_sections * 0.5)
    
    # Calculate how many SEC_REWRITE sections are needed (2% of total sections)
    num_rewrite = int(total_sections * 0.02)
    
    # We generate a fully random cycle and check if it contains valid positions 
    # for our special sections. If not, we shuffle again.
    while True:
        middle_sections = list(range(1, N))
        random.shuffle(middle_sections)
        order = [0] + middle_sections + [N]
        
        # 1. Identify candidates in the last 20% of the cycle for SEC_REAL_FLAG and SEC_FAKE_FLAG
        # Margin constraints are applied to the execution index i.
        candidates_20 = [
            i for i in range(last_20_percent_start, N) 
            if margin <= i <= (N - margin)
        ]
        if len(candidates_20) < 2:
            continue  # Re-shuffle if we don't have enough candidates
            
        # Select two distinct random positions for SEC_REAL_FLAG and SEC_FAKE_FLAG
        idx_two, idx_three = random.sample(candidates_20, 2)
        
        # 2. Identify candidates in the last 50% of the cycle for SEC_SABOTAGE
        # SEC_SABOTAGE must run before SEC_REAL_FLAG and SEC_FAKE_FLAG, so it must be < min(idx_two, idx_three).
        limit = min(idx_two, idx_three)
        candidates_50 = [
            i for i in range(last_50_percent_start, limit)
            if margin <= i <= (N - margin)
        ]
        if not candidates_50:
            continue  # Re-shuffle if no candidates fit the criteria
            
        # Select a random position for SEC_SABOTAGE
        idx_one = random.choice(candidates_50)
        
        # 3. Identify candidates for SEC_REWRITE
        # Filter all middle indices that respect the margin, excluding the other special sections
        candidates_rewrite = [
            i for i in range(1, N)
            if margin <= i <= (N - margin)
            and i not in (idx_one, idx_two, idx_three)
        ]
        if len(candidates_rewrite) < num_rewrite:
            continue
            
        # Select 2% of the sections randomly for SEC_REWRITE
        idx_rewrite_set = set(random.sample(candidates_rewrite, num_rewrite))
        break

    # Extract the chosen section values based on the valid randomized positions
    val_one = order[idx_one]
    val_two = order[idx_two]
    val_three = order[idx_three]
    vals_rewrite = {order[idx] for idx in idx_rewrite_set}
    
    # Build map structures to track previous and next transitions
    next_map = {}
    prev_map = {0: -1}
    for idx in range(N):
        curr = order[idx]
        nxt = order[idx + 1]
        next_map[curr] = nxt
        prev_map[nxt] = curr
        
    # The last normal section before end_sec
    last_sec = order[N - 1]
    
    # Generate keytable
    keytable = list(range(N))
    random.shuffle(keytable)
    
    # Swap elements to enforce keytable[last_sec] == last_sec
    current_idx_of_last_sec = keytable.index(last_sec)
    keytable[current_idx_of_last_sec] = keytable[last_sec]
    keytable[last_sec] = last_sec
    
    # Generate fdtable
    fdtable = [next_map[i] for i in range(N)]
    
    # Map the chosen section numbers to their corresponding macro names
    special_macros = {
        val_one: "SEC_SABOTAGE",
        val_two: "SEC_REAL_FLAG",
        val_three: "SEC_FAKE_FLAG"
    }
    for val in vals_rewrite:
        special_macros[val] = "SEC_REWRITE"
    
    # Generate junktable and junktable2 entries
    # If the section ID (i) corresponds to a non-normal section, set it to NULL
    junktable_entries = []
    junktable2_entries = []
    for i in range(N):
        macro_name = special_macros.get(i, "SEC_NORMAL")
        if macro_name == "SEC_NORMAL":
            junktable_entries.append(f"junk_{random.randint(0, 19)}")
            junktable2_entries.append(f"junk_{random.randint(0, 19)}")
        else:
            junktable_entries.append("NULL")
            junktable2_entries.append("NULL")
    
    # Write the generated.h file
    with open(filename, "w") as f:
        f.write(f"#define LAST_SEC {last_sec}\n")
        f.write(f"#define N_SEC {total_sections - 1}\n")
        f.write(f"#define MOD_VAL {mod_val}\n\n")
        
        # Write keytable
        keytable_str = ", ".join(map(str, keytable))
        f.write(f'__attribute__((section(".keysec"))) int keytable[] = {{{keytable_str}}};\n')
        
        # Write fdtable
        fdtable_str = ", ".join(map(str, fdtable))
        f.write(f'__attribute__((section(".keysec"))) int fdtable[] = {{{fdtable_str}}};\n')
        
        # Write junktable
        junktable_str = ", ".join(junktable_entries)
        f.write(f'__attribute__((section(".keysec"))) void* junktable[] = {{{junktable_str}}};\n')

        # Write junktable2
        junktable2_str = ", ".join(junktable2_entries)
        f.write(f'__attribute__((section(".keysec"))) void* junktable2[] = {{{junktable2_str}}};\n\n')
        
        # Write definitions for each section index (0 to 1022)
        for i in range(N):
            junk_val = junktable_entries[i]
            junk_val_2 = junktable2_entries[i]
            macro_name = special_macros.get(i, "SEC_NORMAL")
            prev = prev_map[i]
            prev_key = keytable[prev] if prev != -1 else -1
            
            if macro_name == "SEC_NORMAL":
                nxt = (0 if i == last_sec else 1)
                nxt_key = keytable[next_map[i]] if next_map[i] < N else N
                next_mod = next_map[i] % mod_val
                f.write(f"{macro_name}({junk_val}, {junk_val_2}, {i}, {nxt}, {nxt_key}, {prev}, {prev_key}, {next_mod})\n")
            elif macro_name == "SEC_REWRITE":
                nxt = next_map[i]
                nxt_key = keytable[nxt] if nxt < N else N
                next_mod = nxt % mod_val
                curr_key = keytable[i]
                f.write(f"{macro_name}({i}, {nxt}, {nxt_key}, {prev}, {prev_key}, {next_mod}, {curr_key})\n")
            else:
                nxt = next_map[i]
                nxt_key = keytable[nxt] if nxt < N else N
                f.write(f"{macro_name}({i}, {nxt}, {nxt_key}, {prev}, {prev_key})\n")
            
        # Write the fns array representing all normal sections
        fns_elements = ", ".join(f"section_{i}" for i in range(N)) + ", NULL"
        f.write(f"\nvoid* fns[] = {{{fns_elements}}};\n")

    # Print out the locations of all non-normal sections
    print("\nNon-normal sections locations:")
    print(f"  SEC_SABOTAGE  -> Section ID: {val_one:<5} Execution Order Index: {idx_one}")
    print(f"  SEC_REAL_FLAG -> Section ID: {val_two:<5} Execution Order Index: {idx_two}")
    print(f"  SEC_FAKE_FLAG -> Section ID: {val_three:<5} Execution Order Index: {idx_three}")
    for idx in sorted(idx_rewrite_set):
        val = order[idx]
        print(f"  SEC_REWRITE   -> Section ID: {val:<5} Execution Order Index: {idx}")
    print()

if __name__ == "__main__":
    generate_header("generated.h", total_sections=512, margin=50, max_thd=8)
    print("generated.h has been successfully created.")
    os.system("gcc -no-pie -fno-pic main.c -O0 -static -s -o chal && ./chal")
