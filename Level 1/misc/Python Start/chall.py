import sys # What's wrong with you, Rootsquare?

def filter_code(user_input): # You cannot use those words.
    banned_word=['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write', 'sh', 'break', 'mro', 'cat', 'flag']
    for i in range(0,len(banned_word),1):
        x=banned_word[i]
        if x in user_input:
            return False
    return True

print("Welcome to Python Challenge! Input your code and capture the flag!")
code=input('Input code > ') # Please input your code.
result=filter_code(code) # Check if you used banned word.

if result==True: # If you follow my rule, then I execute your code.
    try:
        exec(code) # (*) Search what does 'exec' means!
    except:
        pass
else:
    print('Your input is blocked.')
