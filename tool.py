from main import encrypt, Lexer, Parser, File

answer = input("""
        Hey Pr0, What you wanna do(?)
        Press 1 for Encrypting text
        Press 2 for Decrypting text
        \n
        """)
if answer == "1":
    text = input("Tell me what you wanna encrypt: ")
    new_l = Lexer(encrypt(text))
    new_l.create_encrypted()
    new_l.create_schema()
    print(new_l.generate_files())
elif answer == "2":
    enc = input("Enter the exact path of the encrypted file: ")
    sch = input("Enter the exact path of the schema file: ")
    dec = Parser(File(enc).read(), File(sch).read())
    print("Here goes the decrypted string" + "\n" + "==========================HALO10=============================" + "\n" + dec.decrypt())
else:
    print("Simp.. that's an incorrect try")
