'''
Checks whether your password has been compromised 
'''

import sys
import hashlib
import requests

def request_api_data(query_char):
    '''
    Sends a GET request to api.pwnedpasswords.com, and returns the Response object
    '''
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url, timeout=60)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leak_count(hashes, hash_to_check):
    '''
    Checks whether hash_to_check (your pswd) is in hashes (pwned pswds), and returns the count 
    '''
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for pwned_hash, count in hashes:
        if pwned_hash == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    '''
    Returns the count of your pswd in pwnedpasswords.com database
    '''
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    print(first5_char, tail)
    return get_password_leak_count(response, tail)

def main(args):
    '''
    Main function of the program
    '''
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
