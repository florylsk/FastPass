# FastPass

Simple and intuitive tool to store credentials with 128 bit AES in Galois/Counter mode in a SQLite3 database. Supports different keys for different passwords. GUI coming soon.

# Usage
There are two main modes, interactive and non-interactive. Interactive is self-explanatory. For non-interactive:
```text
usage: python3 FastPass.py [-h] [-s] [-u USERNAME] [-p PASSWORD] [-w WEBSITE]
                           [-r] [-k KEY]

Store credentials with AES Galois/Counter mode 128b encryption. You can also
use different master keys to encrypt and decrypt different passwords in the
same database. Do not add arguments for interactive mode

optional arguments:
  -h, --help            show this help message and exit
  -s, --store           Store the credentials in the database
  -u USERNAME, --username USERNAME
                        Username to encrypt
  -p PASSWORD, --password PASSWORD
                        Password to encrypt
  -w WEBSITE, --website WEBSITE
                        Website/company/usage of the credentials (unencrypted)
  -r, --read            Read the current database with a master key
  -k KEY, --key KEY     Master key used to unencrypt some/all the credentials
  
Example usage:

$python3 FastPass.py --store -u Test -p Var -w Google -k TestVar123456789

$python3 FastPass.py --read -k TestVar123456789
```
