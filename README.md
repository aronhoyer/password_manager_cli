# Rust password manager CLI

**IMPORTANT NOTE**
I am not a security expert, and this project is very much based on [Computerphile's video on how password managers work](https://youtu.be/w68BBPDAWr8).

This is a pet project for me to learn Rust. Do not rely on this CLI to safely store your password. If anyone has access to your computer, the vault is already considered breached.

## Installation

TBD

## Vault encryption

To derive a vault key that is used to encrypt the vault, your password is first hashed using pbkdf2, then your password is appended to the derived hash, and hashed again.

When we have the vault key, we can encrypt and decrypt your vault using AES.
