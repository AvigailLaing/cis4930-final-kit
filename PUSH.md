# Pushing this repo

One time, on your Mac, from inside the `repo` folder:

```bash
git init -b main
git add .
git commit -m "CIS4930 final kit: red persistence, blue detection and patching"
```

Then create an empty repo on GitHub (private or public, either works), and:

```bash
git remote add origin https://github.com/<your-user>/<repo-name>.git
git push -u origin main
```

If GitHub asks for a password, it wants a personal access token, not your account password:
GitHub -> Settings -> Developer settings -> Personal access tokens -> generate one with `repo` scope,
and paste it when git asks for the password.

## On the pod, before the final

```bash
git clone https://github.com/<your-user>/<repo-name>.git final-kit
cd final-kit
bash red.sh help
bash blue.sh help
```

If the pod has no outbound internet, fall back to the base64 paste in TRANSFER.txt.

## Before you push, check

- no credentials, keys, or passwords in any file
- no lab PDFs with your personal info other than the two you want in `docs/`
- `bash -n` parses on every shell script
- the README still matches what is actually in the folders
