# Places to update
* `desktop/Cargo.toml`: update the version
* `electron/package.json`: update the version
* `electron/src/pages/Home.tsx`: update version and "what's new" section
* `electron/src/pages/About.tsx`: update version and release notes.

# Land code and build binaries

* Find the commit you want to use a release:
* `git checkout COMMIT`
* For MacOS: ./mac-os-universal-build.sh 
* For Windows: TODO
* Copy artifacts to topology server: `scripts/copy-desktop-binaries.sh`. Currently only does MacOS

# Tag the Release

```
COMMIT=a_nice_commit_hash
VERSION=vX.Y.Z
git checkout $COMMIT
git tag VERSION $COMMIT
git push origin $VERSION
```
