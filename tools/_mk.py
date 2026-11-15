import sys
sys.path.insert(0, r'C:\Users\maxwall\Desktop\DSH空间\pocketled\tools')
import dexlib, dexbuild, rebuild_test

src = open(r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.zh.bak', 'rb').read()
if len(sys.argv) > 1 and sys.argv[1] == 'raw':
    dexbuild.RAW_CODE = True
dx = dexlib.Dex(src)
out = dexbuild.build(rebuild_test.spec_from(dx))
open(r'C:\Users\maxwall\Desktop\DSH空间\pocketled\work\classes.dex', 'wb').write(out)
print(len(out))
