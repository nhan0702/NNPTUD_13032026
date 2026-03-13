# Keys folder for RS256 JWT

## Important: Keep private.key SECRET!

### Files in this folder:
- `private.key` - Private key (NEVER commit to git)
- `public.key` - Public key (safe to share)

### .gitignore
Make sure private.key is in .gitignore:
```
private.key
*.key
```

### Generate Keys
To generate new keys, run from root directory:
```bash
node generateKeys.js
```

This will create:
- `keys/private.key` - Used to SIGN tokens
- `keys/public.key` - Used to VERIFY tokens
