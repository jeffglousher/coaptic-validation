import hashlib
import json
import pathlib
import urllib.request
import zipfile

root = pathlib.Path('D:/coaptic-tools/benchmark-go-1.26.0')
root.mkdir(exist_ok=True)
with urllib.request.urlopen('https://go.dev/dl/?mode=json&include=all', timeout=30) as response:
    data = response.read(8 * 1024 * 1024)
releases = json.loads(data)
release = next(x for x in releases if x['version'] == 'go1.26.0')
file = next(x for x in release['files'] if x['os'] == 'windows' and x['arch'] == 'amd64' and x['kind'] == 'archive')
archive = root / file['filename']
if not archive.exists():
    with urllib.request.urlopen('https://go.dev/dl/' + file['filename'], timeout=60) as source, archive.open('xb') as dest:
        while chunk := source.read(1024 * 1024):
            dest.write(chunk)
assert hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() == file['sha256']
if not (root/'go/bin/go.exe').exists():
    with zipfile.ZipFile(archive) as zipped:
        assert all((root/name).resolve().is_relative_to(root.resolve()) for name in zipped.namelist())
        zipped.extractall(root)
(root/'provenance.json').write_text(json.dumps(file, indent=2))
print(json.dumps(file))
