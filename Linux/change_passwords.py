import os
import random

from passlib.hash import sha512_crypt

shadow_file = "shadow.txt"
users = ["root"]

char_set = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^'
password_length = 15

def generate_password(password_length, char_set):
	password = ""
	for i in range(password_length):
		c = random.choice(char_set)
		password += c
	return password


def generate_password_hash(password):
	hash = sha512_crypt.using(rounds=5000).hash(password)
	return hash

def change_password(user, shadow_file):
	with open(shadow_file, "r") as pass_file:
		shadow_users = pass_file.readlines()

	new_shadow_contents = ""

	for u in shadow_users:
		u_splitted = u.split(":")
		
		username = u_splitted[0]

		if username == user:
			new_password = generate_password(15, char_set)
			new_password_hash = generate_password_hash(new_password)

			print("[+] Changing password for " + username)
			print("[!] New password: " + new_password)

			u_splitted[1] = new_password_hash
		
		new_shadow_contents += ":".join(u_splitted)

	with open(shadow_file, "w") as pass_file:
		pass_file.write(new_shadow_contents)

change_password("wazuh", shadow_file)