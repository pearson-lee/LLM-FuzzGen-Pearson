## Creating Patches
```bash
# For new changes to fuzz-introspector
cd fuzz-introspector
git diff > ../patches/fuzz-introspector.patch

# For new changes to oss-fuzz
cd oss-fuzz
git diff > ../patches/oss-fuzz.patch
```