import socket, threading
from chall import gen_instance

def hexu(x): return format(x,"x")

def recv_line(conn, limit=1<<20):
    buf=b""
    while b"\n" not in buf:
        chunk=conn.recv(4096)
        if not chunk: break
        buf+=chunk
        if len(buf)>limit: break
    i=buf.find(b"\n")
    if i==-1: return buf.decode(errors="ignore").strip()
    return buf[:i].decode(errors="ignore").strip()

def handle(conn):
    try:
        conn.settimeout(10) 
        inst = gen_instance(1024,65537)
        n,e,m_leak,s_good,s_bad,m_target = (
            inst["n"],inst["e"],inst["m_leak"],inst["s_good"],inst["s_bad"],inst["m_target"]
        )
        out=[
            "n="+hexu(n),
            "e="+hexu(e),
            "m_leak="+hexu(m_leak),
            "s_good="+hexu(s_good),
            "s_bad="+hexu(s_bad),
            "m_target="+hexu(m_target),
            "send sig=<hex> then newline (10s limit)",
        ]
        conn.sendall(("\n".join(out)+"\n").encode())
        conn.sendall(("> ").encode())
        line=recv_line(conn)
        if "sig=" not in line:
            conn.sendall(b"Nope.\n"); return
        sig_hex=line.split("=",1)[1].strip()
        try: s=int(sig_hex,16)
        except: conn.sendall(b"Nope.\n"); return
        if pow(s,e,n)!=m_target:
            conn.sendall(b"Nope.\n"); return
        with open("flag.txt","r",encoding="utf-8") as f:
            conn.sendall((f.read().strip()+"\n").encode())
    except Exception:
        try: conn.sendall(b"Timeout.\n")
        except: pass
    finally:
        conn.close()

def main():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("0.0.0.0",8888))
    s.listen(128)
    while True:
        c,_=s.accept()
        threading.Thread(target=handle,args=(c,),daemon=True).start()

if __name__=="__main__":
    main()
