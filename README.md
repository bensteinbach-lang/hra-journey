# hra-journey

Password-protected view of the HRA Completion Journey, served from GitHub Pages. Same approach as `wr-demo`.

| File | What it is |
|---|---|
| `index.html` | The password gate. No content and no secrets. |
| `payload.enc.json` | AES-256-GCM ciphertext of the page (key from PBKDF2-SHA256, 600,000 iterations). |
| `tools/encrypt.mjs` | Builds the payload from `source.html`. |
| `source.html` | The readable page. **Gitignored: keep it local.** |

A wrong password fails to decrypt, so decryption is the password check. The password isn't stored anywhere in the repo. Use a long one and send it separately from the link.

## Update the page or change the password

```
node tools/encrypt.mjs
git commit -am "Rebuild payload"
git push
```

The script asks for the password twice with hidden input. Pages redeploys on push.
