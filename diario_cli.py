from diario import Diario
import sys
import hashlib
import time

#api = Diario("API_ID", "SECRET")

#response = api.search('4b531df5f0fde4dbf8025d2549bfef8cdba71ae3920e783ddd11ec391e3e54a0')
#response = api.search('a38709c129b4fdcd8341a637bec8f4a74dcb5ac095fda3afbd20bf8895c196ee')
#response = api.search('8fa2096bb2d3609be32e1fec48d9467e6e5c205d400e0372d228c3fb6f5e9619')

#response_data = response.data
#response_error = response.error


def get_hash(path):
    with open(path, "rb") as f:
        fbytes = f.read()
        sha256 = hashlib.sha256(fbytes).hexdigest()
    return(sha256)


def check_file(hash):
    api = Diario("API_ID","SECRET")
    resp = api.search(hash)
    resp_data = resp.data
    resp_error = resp.error
    # print(resp_data)

    if resp_data == None:
        #print("Document not found")
        upload_file(sys.argv[1])
        exit()

    elif resp_data["prediction"] == "M":
        print("Malware")
        exit()

    elif resp_data["prediction"] == "NM":
        print("Analyzed: Clean - No Macro - Goodware :)")
        exit()

    elif resp_data["prediction"] == "G":
        print("Analyzed: Clean - Goodware :)")
        exit()

    elif resp_data["prediction"] == "U":
        print("Analyzed: Unknown")
        exit()
        # return(1)
        # upload_file(sys.argv[1])
    else:
        return(0)


def upload_file(path):
    api = Diario("API_ID","SECRET")
    resp = api.upload(path)
    resp_d = resp.data
    resp_e = resp.error
    print("DATA:")
    print(resp_d)
    print("ERROR:")
    print(resp_e)
    print("Requesting new analysis")
    time.sleep(4)
    check_file(resp_d["hash"])


def main():
    hash = get_hash(sys.argv[1])
    check_file(hash)


if __name__ == '__main__':
    main()
