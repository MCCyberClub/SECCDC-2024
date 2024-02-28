import os
import random

from passlib.hash import sha512_crypt

SHADOW_FILE = "/etc/passwd"
USERS = ["root"]
CHAR_SET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^'
PASSWORD_LENGTH = 15

def generate_password():
	password = ""
	for i in range(PASSWORD_LENGTH):
		c = random.choice(CHAR_SET)
		password += c
	return password


def generate_password_hash(password):
	hash = sha512_crypt.using(rounds=5000).hash(password)
	return hash

def change_password(user):
	with open(SHADOW_FILE, "r") as pass_file:
		shadow_users = pass_file.readlines()

	new_shadow_contents = ""

	for u in shadow_users:
		u_splitted = u.split(":")
		
		username = u_splitted[0]

		if username == user:
			new_password = generate_password(PASSWORD_LENGTH, CHAR_SET)
			new_password_hash = generate_password_hash(new_password)

			print("[+] Changing password for " + username)
			print("[!] New password: " + new_password)

			u_splitted[1] = new_password_hash
		
		new_shadow_contents += ":".join(u_splitted)

	with open(SHADOW_FILE, "w") as pass_file:
		pass_file.write(new_shadow_contents)


# EXECUTING IT
for user in USERS:
	change_password(user)