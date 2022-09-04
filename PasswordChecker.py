import requests
import hashlib # putem face sha-1 hashing direct din python
import sys
# 400 not good, 200 ok


def request_api_data(query_char):
    url = 'https:/g/api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    print(res)
    if res.status_code !=200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    #check password if it exists in api response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    print(sha1password)
    first5_char, tail = sha1password[:5], sha1password[5:]
    print(first5_char)
    response = request_api_data(first5_char)
    print(response.text)
    return get_password_leaks_count(response, tail)

 # main function to run in terminal by giving a password
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change your pass')
        else:
            print(f'{password} was not found')
    return 'done'

print(sys.argv[1:])

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

