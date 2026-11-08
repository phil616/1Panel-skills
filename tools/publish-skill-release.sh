#!/usr/bin/env bash
# Publish only a new, fully verified draft; never overwrite an existing release.
set -euo pipefail
: "${GH_REPO:?Set GH_REPO}"
: "${RELEASE_TAG:?Set RELEASE_TAG}"
: "${EXPECTED_SHA:?Set EXPECTED_SHA}"
[[ "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo 'Expected stable SemVer tag, such as v0.1.0' >&2; exit 1;
}
[[ $# == 1 ]] || { echo 'Expected a release asset directory' >&2; exit 1; }
asset_dir=$(cd "$1" && pwd)
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive="1panel-skills-$RELEASE_TAG.zip"
python3 "$repo_dir/tools/skill_zip.py" verify \
  --archive "$asset_dir/$archive" --version "$RELEASE_TAG" --commit "$EXPECTED_SHA"
cd "$asset_dir"
python3 - "$archive" <<'PY'
import hashlib, pathlib, sys
name=sys.argv[1]
expected={name, 'SHA256SUMS', 'RELEASE_NOTES.md'}
if {p.name for p in pathlib.Path('.').iterdir()} != expected:
    raise SystemExit('Unexpected release asset set')
for filename in expected:
    p=pathlib.Path(filename)
    if p.is_symlink() or not p.is_file() or not p.stat().st_size:
        raise SystemExit('Missing, empty or linked release asset')
digest=hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
if pathlib.Path('SHA256SUMS').read_text() != f'{digest}  {name}\n':
    raise SystemExit('ZIP checksum differs from build artifact')
PY
actual_sha=$(gh api "repos/$GH_REPO/commits/$RELEASE_TAG" --jq .sha)
[[ "$actual_sha" == "$EXPECTED_SHA" ]] || {
  echo 'Remote tag differs from the verified source commit' >&2; exit 1;
}
# An authenticated lookup failure aborts; it is never treated as an absent release.
existing=$(gh api --paginate "repos/$GH_REPO/releases?per_page=100" --jq '.[].tag_name')
while IFS= read -r existing_tag; do
  if [[ "$existing_tag" == "$RELEASE_TAG" ]]; then
    echo 'Release/draft exists: inspect it before an explicit recovery; no overwrite' >&2
    exit 1
  fi
done <<< "$existing"
gh release create "$RELEASE_TAG" "$archive" SHA256SUMS --repo "$GH_REPO" \
  --verify-tag --draft --title "1Panel Skills $RELEASE_TAG" --notes-file RELEASE_NOTES.md
remote_manifest=$(mktemp)
download_dir=$(mktemp -d)
trap 'rm -f "$remote_manifest"; rm -rf "$download_dir"' EXIT
gh release view "$RELEASE_TAG" --repo "$GH_REPO" --json isDraft,assets > "$remote_manifest"
python3 - "$remote_manifest" "$archive" <<'PY'
import hashlib,json,pathlib,sys
release=json.load(open(sys.argv[1]))
expected={sys.argv[2],'SHA256SUMS'}
if not release['isDraft'] or {a['name'] for a in release['assets']} != expected:
    raise SystemExit('Expected a draft with the exact complete asset set')
for asset in release['assets']:
    p=pathlib.Path(asset['name'])
    if asset['size'] != p.stat().st_size:
        raise SystemExit('Remote asset size mismatch; leave draft for inspection')
    if asset.get('digest') and asset['digest'] != 'sha256:'+hashlib.sha256(p.read_bytes()).hexdigest():
        raise SystemExit('Remote digest mismatch; leave draft for inspection')
PY
# Download from GitHub before publishing, then compare the exact final bytes.
gh release download "$RELEASE_TAG" --repo "$GH_REPO" \
  --pattern "$archive" --pattern SHA256SUMS --dir "$download_dir"
cmp "$archive" "$download_dir/$archive"
cmp SHA256SUMS "$download_dir/SHA256SUMS"
gh release edit "$RELEASE_TAG" --repo "$GH_REPO" --draft=false --latest
