# Password Strength Analyzer — Enhanced Edition

## Features
- Live password analysis and strength score.
- Length, character diversity, common-password, repeated-character and keyboard-pattern checks.
- Approximate entropy estimate.
- Improvement recommendations.
- Secure random password generation using Python `secrets`.
- Random passphrase generation.
- Copy generated passwords to clipboard.
- Local password history using salted PBKDF2-HMAC-SHA256 hashes.
- Password reuse check against this app's local history.
- Password history table and delete-history option.
- Exportable text report that does not include the password.

## Requirements
- Python 3.10+
- Tkinter (included with most standard Windows Python installers)
- No third-party packages required.

## Run on Windows / VS Code
Open PowerShell in this folder and run:

```powershell
python --version
python main.py
```

If the GUI does not open, test Tkinter:

```powershell
python -m tkinter
```

## Important security limitations
- This is an educational demonstration, not a production password manager.
- Entropy is a rough theoretical estimate and does not model human choices or actual attacker strategies.
- The built-in common-password list is small and is not a full breach database.
- Password reuse checks only entries previously saved in this local app.
- Do not enter real account passwords. Use test values.
- Generated passwords are copied to the clipboard; clear it after use.
- The app stores only salted PBKDF2 hashes, not plaintext passwords.
