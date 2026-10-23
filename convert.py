import re
import os

def load_aux(aux_path):
    labels = {}
    citations = {}
    if not os.path.exists(aux_path):
        print(f"Warning: {aux_path} not found.")
        return labels, citations

    with open(aux_path, 'r', encoding='utf-8') as f:
        content = f.read()

    for line in content.splitlines():
        if line.startswith(r'\newlabel{'):
            key_match = re.match(r'\\newlabel\{([^}]+)\}', line)
            if key_match:
                key = key_match.group(1)
                rest = line[key_match.end():]
                if rest.startswith('{{'):
                    sub_arg = ''
                    brace_count = 0
                    idx = 1
                    while idx < len(rest):
                        char = rest[idx]
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                sub_arg = rest[2:idx]
                                break
                        idx += 1
                    labels[key] = sub_arg
        elif line.startswith(r'\bibcite{'):
            cite_match = re.match(r'\\bibcite\{([^}]+)\}\{([^}]+)\}', line)
            if cite_match:
                key, num = cite_match.groups()
                citations[key] = num

    return labels, citations

def convert_latex_to_md(tex_path, aux_path, md_path):
    labels, citations = load_aux(aux_path)

    with open(tex_path, 'r', encoding='utf-8') as f:
        full_text = f.read()

    # Step 1: Strip comment lines from full text
    full_text = re.sub(r'^\s*%.*$', '', full_text, flags=re.MULTILINE)

    # Step 2: Extract Title, Author, Date, Affiliations from preamble
    preamble_end = full_text.find(r'\begin{document}')
    if preamble_end != -1:
        preamble_text = full_text[:preamble_end]
    else:
        preamble_text = full_text

    title = ""
    author = ""
    date = ""
    affil = []

    title_match = re.search(r'\\title\{((?:[^{}]|\{[^{}]*\})*)\}', preamble_text, re.DOTALL)
    if title_match:
        title = title_match.group(1).replace(r'\textbf', '').replace(r'\\', ' ').strip()
        title = re.sub(r'\{([^}]+)\}', r'\1', title)
        title = re.sub(r'\s+', ' ', title)

    author_match = re.search(r'\\author\{((?:[^{}]|\{[^{}]*\})*)\}', preamble_text, re.DOTALL)
    if author_match:
        author = author_match.group(1).strip()
        author = re.sub(r'\\orcidlink\{[^}]+\}', '', author)
        author = author.replace('~', ' ')
        author = re.sub(r'\s+', ' ', author)

    date_match = re.search(r'\\date\{((?:[^{}]|\{[^{}]*\})*)\}', preamble_text, re.DOTALL)
    if date_match:
        date = date_match.group(1).strip()

    affil_matches = re.findall(r'\\affil\{((?:[^{}]|\{[^{}]*\})*)\}', preamble_text, re.DOTALL)
    for aff in affil_matches:
        cleaned_aff = aff.replace(r'\\', ',').replace(r'\texttt', '').strip()
        cleaned_aff = re.sub(r'\{([^}]+)\}', r'\1', cleaned_aff)
        cleaned_aff = re.sub(r'\s+', ' ', cleaned_aff)
        affil.append(cleaned_aff)

    # Macro definitions mapping
    macros = {
        r'\negl': r'\mathsf{negl}',
        r'\Adv': r'\mathbf{Adv}',
        r'\PGame': r'\mathbf{Game}',
        r'\calA': r'\mathcal{A}',
        r'\calB': r'\mathcal{B}',
        r'\calS': r'\mathcal{S}',
        r'\calK': r'\mathcal{K}',
        r'\calO': r'\mathcal{O}',
        r'\bits': r'\{0,1\}',
        r'\getsr': r'\stackrel{\$}{\leftarrow}',
        r'\MLKEM': r'\mathsf{ML\text{-}KEM}',
        r'\MLDSA': r'\mathsf{ML\text{-}DSA}',
        r'\HKDF': r'\mathsf{HKDF}',
        r'\HKDFExtract': r'\mathsf{HKDFExtract}',
        r'\HKDFExpand': r'\mathsf{HKDFExpand}',
        r'\HMAC': r'\mathsf{HMAC}',
        r'\DHop': r'\mathsf{DH}',
        r'\Encaps': r'\mathsf{Encaps}',
        r'\Decaps': r'\mathsf{Decaps}',
        r'\Sign': r'\mathsf{Sign}',
        r'\Verify': r'\mathsf{Verify}',
        r'\KeyGen': r'\mathsf{KeyGen}',
    }

    def extract_braced_arg(text, pos):
        start = text.find('{', pos)
        if start == -1:
            return None, pos
        depth = 1
        i = start + 1
        while i < len(text):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    return text[start+1:i], i + 1
            i += 1
        return None, len(text)

    def expand_balanced_macro(macro_name, formatter, text):
        needle = '\\' + macro_name
        while needle in text:
            idx = text.find(needle)
            if idx == -1:
                break
            after_cmd = idx + len(needle)
            if after_cmd < len(text) and text[after_cmd].isalpha():
                break
            arg, next_pos = extract_braced_arg(text, after_cmd)
            if arg is None:
                break
            text = text[:idx] + formatter(arg) + text[next_pos:]
        return text

    def expand_macros(text):
        for macro, replacement in macros.items():
            pattern = re.escape(macro) + r'(?![a-zA-Z])'
            text = re.sub(pattern, lambda m, r=replacement: r, text)

        # Handle \bigcat
        while r'\bigcat' in text:
            idx = text.find(r'\bigcat')
            if idx == -1:
                break
            after = idx + len(r'\bigcat')
            arg1, next_pos = extract_braced_arg(text, after)
            if arg1 is None:
                break
            rest = text[next_pos:]
            match_ws = re.match(r'^\s*\{', rest)
            if match_ws:
                arg2, final_pos = extract_braced_arg(text, next_pos)
                text = text[:idx] + f'\\mathop{{\\Vert}}_{{{arg1}}} {arg2}' + text[final_pos:]
            else:
                text = text[:idx] + f'\\mathop{{\\Vert}}_{{{arg1}}}' + text[next_pos:]

        text = expand_balanced_macro('flen', lambda a: f'\\mathsf{{len}}_{{32}}({a})', text)
        text = expand_balanced_macro('hexlit', lambda a: f'\\mathtt{{{a}}}', text)
        text = expand_balanced_macro('strlit', lambda a: f'\\text{{"{a}"}}', text)
        text = expand_balanced_macro('footnote', lambda a: f' (* {a.strip()} *)', text)
        text = re.sub(r'\\Hgame\{((?:[^{}]|\{[^{}]*\})*)\}', lambda m: f'\\mathbf{{H}}_{{{m.group(1)}}}', text)
        return text

    def clean_text(text):
        text = text.replace(r'\maketitle', '')
        text = text.replace(r'\noindent', '')
        text = text.replace(r'\newpage', '')

        text = text.replace('~', ' ')
        text = text.replace('---', '—')
        text = text.replace('--', '–')
        text = text.replace("``", '"').replace("''", '"')
        text = text.replace(r'\,', ' ')
        text = text.replace(r'\ ', ' ')
        text = text.replace(r'\&', '&')
        text = text.replace(r'\#', '#')
        text = text.replace(r'\%', '%')

        def cite_repl_simple(match):
            keys = [k.strip() for k in match.group(1).split(',')]
            links = []
            for k in keys:
                num = citations.get(k, k)
                links.append(f"[{num}](#{k})")
            return ", ".join(links)

        text = re.sub(r'\\cite\{([^}]+)\}', cite_repl_simple, text)

        def ref_repl(match):
            key = match.group(1)
            return labels.get(key, f"[{key}]")
        text = re.sub(r'\\ref\{([^}]+)\}', ref_repl, text)

        text = re.sub(r'\\emph\{((?:[^{}]|\{[^{}]*\})*)\}', lambda m: f'*{m.group(1)}*', text, flags=re.DOTALL)
        text = re.sub(r'\\textbf\{((?:[^{}]|\{[^{}]*\})*)\}', lambda m: f'**{m.group(1)}**', text, flags=re.DOTALL)
        text = re.sub(r'\\texttt\{((?:[^{}]|\{[^{}]*\})*)\}', lambda m: f'`{m.group(1)}`', text, flags=re.DOTALL)
        text = re.sub(r'\\url\{([^}]+)\}', lambda m: f'[{m.group(1)}]({m.group(1)})', text)

        text = text.replace(r"\'e", "é")
        text = text.replace(r"\`e", "è")
        text = text.replace(r"\`i", "ì")
        text = text.replace(r"\`a", "à")
        text = text.replace(r"\`o", "ò")
        text = text.replace(r"\`u", "ù")
        text = text.replace(r"\`es", "ès")

        return text

    doc_start = full_text.find(r'\begin{document}')
    if doc_start != -1:
        body_text = full_text[doc_start:]
    else:
        body_text = full_text

    body_text = expand_macros(body_text)
    body_text = clean_text(body_text)

    lines = body_text.splitlines()

    output = []

    output.append(f"# {title}\n")
    if author:
        output.append(f"**Author:** {author}  ")
    if affil:
        output.append(f"**Affiliation:** {', '.join(affil)}  ")
    if date:
        output.append(f"**Date:** {date}  \n")

    in_abstract = False
    list_stack = []

    sec_count = 0
    subsec_count = 0
    subsubsec_count = 0
    theorem_count = 0

    i = 0
    while i < len(lines):
        line = lines[i]

        if line.strip() in (r'\begin{document}', r'\end{document}'):
            i += 1
            continue

        if r'\begin{abstract}' in line:
            in_abstract = True
            output.append("## Abstract\n")
            i += 1
            continue
        elif r'\end{abstract}' in line:
            in_abstract = False
            output.append("\n")
            i += 1
            continue

        if in_abstract:
            output.append(re.sub(r'\\label\{[^}]+\}', '', line.strip()) + " ")
            i += 1
            continue

        # Headings
        sec_match = re.match(r'\\section\*?\{([^}]+)\}', line)
        if sec_match:
            sec_name = sec_match.group(1)
            sec_name = re.sub(r'\\label\{[^}]+\}', '', sec_name).strip()

            if sec_name.lower() == "acknowledgements":
                output.append(f"\n# Acknowledgements\n")
            else:
                sec_count += 1
                subsec_count = 0
                subsubsec_count = 0
                theorem_count = 0
                output.append(f"\n# {sec_count}. {sec_name}\n")
            i += 1
            continue

        subsec_match = re.match(r'\\subsection\*?\{([^}]+)\}', line)
        if subsec_match:
            subsec_name = subsec_match.group(1)
            subsec_name = re.sub(r'\\label\{[^}]+\}', '', subsec_name).strip()
            subsec_count += 1
            subsubsec_count = 0
            output.append(f"\n## {sec_count}.{subsec_count} {subsec_name}\n")
            i += 1
            continue

        subsubsec_match = re.match(r'\\subsubsection\*?\{([^}]+)\}', line)
        if subsubsec_match:
            subsubsec_name = subsubsec_match.group(1)
            subsubsec_name = re.sub(r'\\label\{[^}]+\}', '', subsubsec_name).strip()
            subsubsec_count += 1
            output.append(f"\n### {sec_count}.{subsec_count}.{subsubsec_count} {subsubsec_name}\n")
            i += 1
            continue

        # Paragraphs
        paragraph_match = re.match(r'^\s*\\paragraph\{([^}]+)\}', line)
        if paragraph_match:
            para_name = paragraph_match.group(1)
            para_name = re.sub(r'\\label\{[^}]+\}', '', para_name).strip()
            output.append(f"\n**{para_name}**\n")
            i += 1
            continue

        # Theorem environments begins
        env_begin_match = re.match(r'\\begin\{(definition|theorem|securityclaim|lemma|corollary|proposition|remark|assumption)\}(\[[^\]]+\])?', line)
        if env_begin_match:
            env_type = env_begin_match.group(1)
            env_name = env_begin_match.group(2)

            env_label = None
            for idx in range(i, min(i+10, len(lines))):
                lbl_match = re.search(r'\\label\{([^}]+)\}', lines[idx])
                if lbl_match:
                    env_label = lbl_match.group(1)
                    break

            theorem_count += 1
            env_num = f"{sec_count}.{theorem_count}"

            env_title_display = env_type.replace('securityclaim', 'Security Claim').capitalize()

            name_str = ""
            if env_name:
                name_str = f" ({env_name[1:-1]})"

            anchor = f"<a id=\"{env_label}\"></a>" if env_label else ""
            output.append(f"\n> {anchor}**{env_title_display} {env_num}{name_str}.** ")
            i += 1
            continue

        env_end_match = re.match(r'\\end\{(definition|theorem|securityclaim|lemma|corollary|proposition|remark|assumption)\}', line)
        if env_end_match:
            output.append("\n")
            i += 1
            continue

        # Proof environment
        proof_begin_match = re.match(r'\\begin\{proof\}(\[[^\]]+\])?', line)
        if proof_begin_match:
            proof_title = proof_begin_match.group(1)
            if proof_title:
                title_str = proof_title[1:-1]
                output.append(f"\n*{title_str}.* ")
            else:
                output.append(f"\n_Proof Sketch._ ")
            i += 1
            continue

        if r'\end{proof}' in line:
            output.append(f" $\\square$\n")
            i += 1
            continue

        if r'\tableofcontents' in line:
            i += 1
            continue

        # Lists
        if r'\begin{itemize}' in line:
            list_stack.append({'type': 'itemize'})
            i += 1
            continue
        elif r'\end{itemize}' in line:
            if list_stack:
                list_stack.pop()
            i += 1
            continue

        if r'\begin{enumerate}' in line:
            list_stack.append({'type': 'enumerate', 'counter': 1})
            i += 1
            continue
        elif r'\end{enumerate}' in line:
            if list_stack:
                list_stack.pop()
            i += 1
            continue

        if r'\item' in line:
            cleaned_item = re.sub(r'\\label\{[^}]+\}', '', line.replace(r'\item', '').strip())
            indent = "  " * (len(list_stack) - 1) if list_stack else ""
            if list_stack and list_stack[-1]['type'] == 'enumerate':
                cnt = list_stack[-1]['counter']
                output.append(f"{indent}{cnt}. {cleaned_item}")
                list_stack[-1]['counter'] += 1
            else:
                output.append(f"{indent}- {cleaned_item}")
            i += 1
            continue

        # Math blocks
        if line.strip() == r'\[':
            math_lines = []
            i += 1
            while i < len(lines) and lines[i].strip() != r'\]':
                math_lines.append(lines[i].strip())
                i += 1
            math_content = " ".join(math_lines)
            output.append(f"\n$$\n{math_content}\n$$\n")
            i += 1
            continue

        # align* environment
        if r'\begin{align*}' in line:
            math_lines = []
            i += 1
            while i < len(lines) and r'\end{align*}' not in lines[i]:
                math_lines.append(lines[i].strip())
                i += 1
            math_content = "\n".join(math_lines)
            output.append(f"\n$$\n\\begin{{aligned}}\n{math_content}\n\\end{{aligned}}\n$$\n")
            i += 1
            continue

        # Hardcode Table replacements to keep them perfect
        if r'\begin{table}' in line:
            table_lines = []
            while i < len(lines) and r'\end{table}' not in lines[i]:
                table_lines.append(lines[i])
                i += 1
            table_lines.append(lines[i])
            table_text = "".join(table_lines)

            if "tab:mixnet_sim" in table_text:
                md_table = """
| Load ($\lambda$) (pkts/slot) | Churn Rate (fraction/slot) | Packet MTU Violations | Delivery Rate | p95 Delay (slots) | Entry–Exit Linkability |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 1.0 | 0.0 | **0** | 100.0% | 3.0 | 12.8% |
| 5.0 | 0.0 | **0** | 100.0% | 4.0 | 3.5% |
| 10.0 | 0.0 | **0** | 95.1% | 279.0 | 2.2% |
| 20.0 | 0.0 | **0** | 31.3% | 3,258.0 | 4.7% |
| 1.0 | 0.1 | **0** | 65.3% | 3.0 | 5.4% |
| 5.0 | 0.1 | **0** | 62.8% | 4.0 | 0.8% |
| 10.0 | 0.1 | **0** | 52.1% | 7.0 | 3.6% |
| 1.0 | 0.2 | **0** | 39.7% | 3.0 | 2.1% |
| 5.0 | 0.2 | **0** | 38.3% | 3.0 | 4.6% |
| 10.0 | 0.2 | **0** | 31.8% | 5.0 | 2.1% |
| 1.0 | 0.3 | **0** | 23.9% | 3.0 | 0.7% |
| 5.0 | 0.3 | **0** | 22.8% | 3.0 | 2.4% |
| 10.0 | 0.3 | **0** | 19.1% | 4.0 | 2.3% |

*Table 1: Empirical mixnet queue simulation results for the signed ratchet design across 13 simulation runs (30 nodes, 3 hops, capacity $C=2$ pkts/node/slot, 1{,}500-byte MTU, 4 fragments per signed update, from `poc/python/mixnet_sim.py`).*
"""
                output.append(md_table)
            elif "tab:primitives" in table_text:
                md_table = """
| Primitive | Public Key | Ciphertext / DH Output | Shared Secret |
| :--- | :--- | :--- | :--- |
| X25519 | 32 B | 32 B | 32 B |
| ML-KEM-768 | 1184 B | 1088 B | 32 B |
| ML-DSA-65 | 1952 B | N/A (sig: 3,309 B) | N/A |

*Table 2: Primitive sizes relevant to Star-Mesh.*
"""
                output.append(md_table)
            elif "tab:overhead" in table_text:
                md_table = """
| Component | Classical (Signal) | Star-Mesh | Overhead |
| :--- | :--- | :--- | :--- |
| *Star-Mesh handshake rows include the 32-byte $tag_A$ confirmation tag.* |||
| Handshake, with OTPK (bytes) | $\\approx 150$ [8](#marlinspike_x3dh) | $\\approx 7,565$ | $+7,415$ |
| Handshake, SPK-only fallback | $\\approx 118$ [8](#marlinspike_x3dh) | $\\approx 6,477$ | $+6,359$ |
| Ratchet header (non-PQ step) | 32 (X25519 pk) | 32 (X25519 pk) | 0 |
| Ratchet step, unsigned (raw KEM pk) | N/A | $+1,184$ (KEM pk) | $+1,184$ |
| Ratchet reply, unsigned (raw KEM ct) | N/A | $+1,088$ (KEM ct) | $+1,088$ |
| Ratchet step, signed ($pk+\\sigma_{\\mathsf{ML\\text{-}DSA}}$) | N/A | $+4,493$ | $+4,493$ |
| Ratchet reply, signed ($ct+\\sigma_{\\mathsf{ML\\text{-}DSA}}$) | N/A | $+4,397$ | $+4,397$ |

*Table 3: Bandwidth overhead comparison. Classical Signal handshake size is derived from the X3DH specification [8](#marlinspike_x3dh): two 32-byte X25519 public keys (IK and EK), one 32-byte SPK, one 32-byte OTPK, and protocol framing, totalling approximately 150 bytes with an initial encrypted message (118 bytes without an OTPK). Bob does not receive his own SPK or OTPK back from Alice. Star-Mesh handshake figures follow the $M_0$ definition of Section 3.4: $IK^{DSA}_{pk,A}$ (1,952 B) $+$ $IK^{DH}_{pk,A}$ (32 B) $+$ $EK_{pk,A}$ (32 B) $+$ $ct_1$ (1,088 B) $+$ optionally $ct_2$ (1,088 B) $+$ 32 B confirmation tag $+$ $\\sigma_0$ signature (3,309 B) $+$ 32 B framing/identifiers $= 7,565$ B with OTPK (7,533 B raw cryptographic payload), 6,477 B without (6,445 B raw cryptographic payload). With a 1,404-byte Sphinx payload capacity, transmitting $M_0$ requires a 6-packet Sphinx train ($\\lceil 7,565 / 1,404 \\rceil = 6$, and 5 packets for SPK-only: $\\lceil 6,477 / 1,404 \\rceil = 5$). The 1,952-byte $IK^{DSA}_{pk,A}$ is transmitted on every handshake as specified; implementations that cache a correspondent's identity key after first contact can amortise this cost across a relationship rather than a session.*
"""
                output.append(md_table)
            i += 1
            continue

        # Bibliography
        if r'\begin{thebibliography}' in line:
            output.append("\n# References\n")
            i += 1
            continue
        elif r'\end{thebibliography}' in line:
            i += 1
            continue

        if r'\bibitem{' in line:
            bib_match = re.match(r'\\bibitem\{([^}]+)\}', line)
            if bib_match:
                bib_key = bib_match.group(1)
                bib_num = citations.get(bib_key, "?")

                bib_text_lines = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith(r'\bibitem') and not lines[i].strip().startswith(r'\end{thebibliography}'):
                    bib_text_lines.append(lines[i].strip())
                    i += 1

                bib_text = " ".join(bib_text_lines)
                bib_text = re.sub(r'\\label\{[^}]+\}', '', bib_text)

                output.append(f"\n{bib_num}. <a id=\"{bib_key}\"></a>{bib_text}\n")
                continue

        cleaned_line = re.sub(r'\\label\{[^}]+\}', '', line)
        output.append(cleaned_line)
        i += 1

    final_content = "\n".join(output)
    final_content = re.sub(r'\n{3,}', '\n\n', final_content)

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(final_content)

    print(f"Successfully converted {tex_path} to {md_path}")

if __name__ == "__main__":
    tex = "paper/paper.tex"
    aux = "paper/paper.aux"
    md = "paper/paper.md"
    convert_latex_to_md(tex, aux, md)
