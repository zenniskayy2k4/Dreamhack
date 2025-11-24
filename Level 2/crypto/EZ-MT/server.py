import socket, threading, time, secrets, random

HOST="0.0.0.0"
PORT=8888
TL=10.0
with open("flag.txt", "rb") as f:
    FLAG = f.read().strip().decode()

def _f(x): return f"{x:0128x}"

def gen(seed):
    r = random.Random(seed)
    a = [_f(r.getrandbits(512)) for _ in range(39)]
    b = _f(r.getrandbits(512))
    return a, b

def seed():
    return int(time.time_ns()) ^ secrets.randbits(64)

def h(conn):
    conn.settimeout(TL)
    try:
        leaks, ans = gen(seed())
        for x in leaks: conn.sendall((x+"\n").encode())
        conn.sendall(b">")
        buf=b""
        while not buf.endswith(b"\n"):
            c=conn.recv(4096)
            if not c: break
            buf+=c
        if buf.strip().lower().decode(errors="ignore")==ans:
            conn.sendall((FLAG+"\n").encode())
        else:
            conn.sendall(b"\n")
    except socket.timeout:
        try: conn.sendall(b"timeout.\n")
        except: pass
    except TimeoutError:
        try: conn.sendall(b"timeout.\n")
        except: pass
    except: 
        try: conn.sendall(b"\n")

        except: pass
    finally:
        try: conn.close()
        except: pass

def main():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((HOST,PORT)); s.listen(5)
    while True:
        c,_=s.accept()
        threading.Thread(target=h,args=(c,),daemon=True).start()

if __name__=="__main__":
    main()
