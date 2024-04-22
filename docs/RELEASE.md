# Places to update
* `desktop/Cargo.toml`: update the version
* `webserver/Cargo.toml`: update the version
* `frontend/electron/package.json`: update the version
* `frontend/electron/src/pages/Home.tsx`: update version and "what's new" section
* `frontend/electron/src/pages/ReleaseNotes.tsx`: update version and release notes.

# Land code and build binaries

* Find the commit you want to use a release:
* `git checkout COMMIT`
* To create the build artifacts, run `./cut-desktop-release.sh` (works on Mac and windows, but not cross-platform building)
* Copy artifacts to topology server: `scripts/copy-desktop-binaries.sh`. Works for both Mac and windows, but no cross-platform building.

# Tag the Release

```
COMMIT=a_nice_commit_hash
VERSION=vX.Y.Z
git checkout $COMMIT
git tag VERSION $COMMIT
git push origin $VERSION
```
