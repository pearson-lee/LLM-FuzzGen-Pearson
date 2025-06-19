## Creating Patches
### For new changes to fuzz-introspector
```bash
cd fuzz-introspector
git diff > ../patches/fuzz-introspector.patch
cd ..
```

### For new changes to oss-fuzz
```bash
cd oss-fuzz
git diff > ../patches/oss-fuzz.patch
cd ..
```