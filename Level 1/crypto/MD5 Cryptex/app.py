from flask import Flask, render_template, request
import secrets
import hashlib

app=Flask(__name__)

letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
password=''
target=None
key = [secrets.randbelow(36) for _ in range(6)]
for i in range(0,6,1):
    password+=letters[key[i]]
target=hashlib.md5(password.encode()).digest().hex()

@app.route('/')
def index():
    return render_template('main.html',target=target,error='Enter the correct password!')

@app.route('/submit', methods=['POST'])
def submit_code():
    data=str(request.form.get('val1'))+str(request.form.get('val2'))+str(request.form.get('val3'))+str(request.form.get('val4'))+str(request.form.get('val5'))+str(request.form.get('val6'))
    attempt=hashlib.md5(data.encode()).digest().hex()
    if target==attempt:
        return render_template('main.html',target=target,error='DH{**flag**}')
    else:
        return render_template('main.html',target=target,error='Incorrect password')

if __name__=='__main__':
    app.run(debug=False,host='0.0.0.0',port=5000)