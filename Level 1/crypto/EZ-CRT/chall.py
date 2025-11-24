import secrets
from math import gcd

def egcd(a,b):
    if b==0: return a,1,0
    g,x,y=egcd(b,a%b)
    return g,y,x-(a//b)*y

def inv(a,m):
    g,x,_=egcd(a,m)
    if g!=1: raise ValueError
    return x%m

def mr(n):
    if n<2: return False
    for p in (2,3,5,7,11,13,17,19,23,29):
        if n%p==0: return n==p
    d=n-1;r=0
    while d%2==0: d//=2; r+=1
    for _ in range(40):
        a=secrets.randbelow(n-3)+2
        x=pow(a,d,n)
        if x==1 or x==n-1: continue
        for __ in range(r-1):
            x=(x*x)%n
            if x==n-1: break
        else:
            return False
    return True

def prime(bits):
    while True:
        x=(1<<(bits-1))|secrets.randbits(bits-2)|1
        if mr(x): return x

def crt(sp,sq,p,q,qinv):
    return (sq + q*(((sp-sq)*qinv)%p))%(p*q)

def gen_instance(bits=1024,e=65537):
    p=prime(bits//2); q=prime(bits//2)
    while p==q: q=prime(bits//2)
    n=p*q
    phi=(p-1)*(q-1)
    if egcd(e,phi)[0]!=1: return gen_instance(bits,e)
    d=inv(e,phi)
    dp=d%(p-1); dq=d%(q-1); qinv=inv(q,p)
    m_leak=secrets.randbelow(n-1)+1
    m_target=secrets.randbelow(n-1)+1
    sp=pow(m_leak,dp,p); sq=pow(m_leak,dq,q)
    s_good=crt(sp,sq,p,q,qinv)
    sq_bad=(sq^1)%q
    s_bad=crt(sp,sq_bad,p,q,qinv)
    g=gcd(abs(s_good-s_bad),n)
    if not (1<g<n and n%g==0): return gen_instance(bits,e)
    return {
        "n":n,"e":e,
        "m_leak":m_leak,"s_good":s_good,"s_bad":s_bad,
        "m_target":m_target,"d":d,"n_factors":(p,q)
    }
