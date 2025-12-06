import bcrypt

# ←– change this to whatever new password you want
new_password = b"admin"

# gensalt(log_rounds) — higher number = more work (default ~12)
salt    = bcrypt.gensalt(rounds=12)
new_hash = bcrypt.hashpw(new_password, salt)

print(new_hash.decode())

