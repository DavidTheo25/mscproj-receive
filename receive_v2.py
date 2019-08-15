import socket
import time
import json
import os
import zipfile
import hashlib
import shutil
from recognize_video import Recognize
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def encrypt_request(request, public_key_path):
    encoded_req = request.encode('utf-8')
    public_key = RSA.import_key(open(public_key_path).read())
    session_key = get_random_bytes(16)

    # encrypt session key with public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # encrypt data with aes session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(encoded_req)

    return str((enc_session_key, cipher_aes.nonce, tag, cipher_text)).encode()


def decrypt_display_email(path_to_message, private_user_key):
    file_in = open(path_to_message, "rb")
    private_key_temp = RSA.import_key(private_user_key)
    enc_session_key, nonce, tag, ciphertext = [file_in.read(x) for x in (private_key_temp.size_in_bytes(), 16, 16, -1)]
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key_temp)
    session_key = cipher_rsa.decrypt(enc_session_key)
    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    message_to_display = cipher_aes.decrypt_and_verify(ciphertext, tag)
    message_text = (message_to_display.decode("utf-8")).split("\n")
    subject = message_text[0]
    content = "".join(message_text[1:])
    # Display
    print("[MESSAGE] ==================================================")
    print("[Subject]", subject)
    print("[content]")
    print(content)
    print("============================================================")
    os.remove(path_to_message)


def receive_file(user, security_token, conn):
    ret = {}
    path_to_file = "fr_data/%s" % user
    if not os.path.exists(path_to_file):
        os.makedirs(path_to_file)
    zipfile = "%s/%s.zip" % (path_to_file, user)
    with open(zipfile, 'wb') as f:
        # print('file opened')
        wtf = 0
        while True:
            # print('receiving data...')
            data_temp = conn.recv(1024)
            # print('data=', repr(data))
            if not data_temp:
                break
            if len(data_temp) >= 3:
                if data_temp[-3:] == b"EOF":
                    f.write(data_temp[:-3])
                    break
            # write data to a file
            f.write(data_temp)
    # extracting security token from the file
    # TODO why not use hash of the file in the future ?
    with open(zipfile, 'rb') as f:
        offset = len(security_token)
        f.seek(-offset, os.SEEK_END)  # Note minus sign
        token_temp = f.read()
        token = token_temp.decode()
    if token == security_token:
        # print("[INFO] Valid Token !!")
        ret["success"] = True
        ret["reason"] = "User %s completely registered" % user
        ret["zipfile"] = zipfile
    else:
        ret["success"] = False
        ret["reason"] = "Wrong token"
        print("[ERROR] Wrong token !!")
        os.remove(zipfile)
    return ret


# TCP_IP = 'localhost'
TCP_IP = "192.168.56.103"
TCP_PORT = 9001
BUFFER_SIZE = 1024

email = input("email address: ")
pswd = input("password: ")
# email = "toplexil40@gmail.com"
# pswd = "bob"
public_key_p = "public1.pem"
# email = hashlib.sha256(email.encode()).hexdigest()
# pswd = hashlib.sha256(pswd.encode()).hexdigest()
# req = "login,%s,%s" % (email, pswd)
# req_to_send = encrypt_request(req, public_key_p)

r = Recognize("face_detection_model", "face_detection_model/openface_nn4.small2.v1.t7")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((TCP_IP, TCP_PORT))
    # s.sendall(req.encode('utf-8'))
    email = hashlib.sha256(email.encode()).hexdigest()
    pswd = hashlib.sha256(pswd.encode()).hexdigest()
    req = "login,%s,%s" % (email, pswd)
    req_to_send = encrypt_request(req, public_key_p)
    s.sendall(req_to_send)
    s.sendall(b"EOR")
    data = s.recv(BUFFER_SIZE)
    res = json.loads(data.decode('utf-8'))
    # print('Received', repr(data))
    print("[INFO] ", res["reason"])
    if "token" in res and "number" in res:
        if res["number"] != 0:
            question = input("You can only see them once !\nDo you want to see them ?(y/n)")
            if question == "y":
                token = res["token"]
                req = "get2,%s,%s,%s" % (email, pswd, token)
                req_to_send = encrypt_request(req, public_key_p)
                # s.sendall(req.encode('utf-8'))
                s.sendall(req_to_send)
                s.sendall(b"EOR")
                res = receive_file(email, token, s)
                if res["success"]:
                    if "zipfile" in res:
                        zipfile_path = res["zipfile"]
                        extract_path = email + "+mail"

                        # extract mail + face recognition zipped data
                        with zipfile.ZipFile(zipfile_path) as myzipfile:
                            myzipfile.extractall(extract_path)
                        path_to_fr_data = extract_path + "/fr_data.zip"

                        # extract face recognition data
                        if os.path.exists(path_to_fr_data):
                            with zipfile.ZipFile(path_to_fr_data) as myzipfile:
                                myzipfile.extractall(email+"_fr")

                            # remove useless dirs and zipfiles
                            os.remove(path_to_fr_data)
                            os.remove(zipfile_path)
                            shutil.rmtree("fr_data/")

                            # check identity
                            recognizer_path = email + "_fr/recognizer.pickle"
                            le_path = email + "_fr/le.pickle"
                            chances = 0
                            id_success = False
                            while chances < 3 and not id_success:
                                chances += 1
                                face_id = r.recognize(recognizer_path, le_path, email)
                                if face_id["success"]:
                                    # delete face recognition data after recognition
                                    shutil.rmtree(email + "_fr")
                                    id_success = True
                                    # ask for the private key now that the facial recognition succeeded
                                    key_request = "get_key,%s,%s,%s" % (email, pswd, token)
                                    key_request_enc = encrypt_request(key_request, public_key_p)
                                    s.sendall(key_request_enc)
                                    s.sendall(b"EOR")
                                    private_key = s.recv(3*BUFFER_SIZE)
                                    # print("[DEBUG] private key: ", private_key)
                                    # Decrypt emails with received key, display them in console then delete them
                                    path_to_mail = email + "+mail"
                                    if os.path.exists(path_to_mail):
                                        for message in os.listdir(path_to_mail):
                                            path_to_email = path_to_mail + "/" + message
                                            decrypt_display_email(path_to_email, private_key)
                                    break
                                print("[WARNING] Face identification failed you can try %s more time(s)" % (3-chances))
                            if not id_success:
                                print("[WARNING] Face identification failed")
                                req = "stop"
                                req_to_send = encrypt_request(req, public_key_p)
                                s.sendall(req_to_send)
                                s.sendall(b"EOR")
                        else:
                            print("[ERROR] no face recognition data")
                    else:
                        print("[ERROR] Wait... this should not happen")
                else:
                    print("[ERROR] Error while receiving zip file")
                # data = s.recv(10*BUFFER_SIZE)
                # res = json.loads(data.decode('utf-8'))
                # print('Received', repr(data))
            else:
                # User does not want to see the emails
                req = "stop"
                req_to_send = encrypt_request(req, public_key_p)
                s.sendall(req_to_send)
                s.sendall(b"EOR")

if os.path.exists(email + "_fr"):
    shutil.rmtree(email + "_fr")

# print('Sent request')
# # s.close()
# print('connection closed')
print("[INFO] finished")
