import re, sys
path = r'C:\Users\maxwall\Desktop\DSH空间\pocketled\code_dump.txt'
skip = re.compile(r'\$r8|\(\$\)V|^\(\)V$|Lambda|\$\$Nest|^\$|^<init>$|^<clinit>$')
lines = open(path, encoding='utf-8').read().split('\n')
for i, l in enumerate(lines):
    if 'const-string' in l:
        s = l.strip()
        m = re.search(r'const-string [^,]+, "(.*)"$', s)
        if m:
            v = m.group(1)
            if skip.search(v) or v.startswith('L') or v.endswith(';') or '/' in v:
                continue
        print(f'{i+1:5d} {s}')
