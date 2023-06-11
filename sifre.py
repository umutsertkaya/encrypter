import rsa
from base64 import b64encode, b64decode
import codecs
import sqlite3


con = sqlite3.connect("easy.db")
sifreli_metin = ""
im = con.cursor()
usrnm = input("Kullanıcı adı:")
pwrm = input("Şifre:")
if usrnm == "new":
     kul = input("Kullanıcı Adı:")
     sif = input("Şifre:")
     im.execute("""INSERT INTO sifre VALUES (?,?,?,?) """,(kul,sif,"b","b"))
     con.commit()
     print("Kullanıcı Kaydedildi...")
im.execute("""SELECT * FROM sifre WHERE usrnm=? """, (usrnm,))
res = im.fetchone()


def encry(g, h):
     global sifreli_metin
     global h2
     h2 = h
     if g == "b" and h == "b":
            (pubk, prik) = rsa.newkeys(2048)
            l = pubk.save_pkcs1().decode()
            m = prik.save_pkcs1().decode()
            im.execute("UPDATE sifre SET pub_key = ? WHERE usrnm = ?", (l, usrnm))
            con.commit()
            im.execute("UPDATE sifre SET pri_key = ? WHERE usrnm = ?", (m, usrnm))
            con.commit()
     else:
        pub = str(g)
        pri = str(h)
        pri2 = rsa.PrivateKey.load_pkcs1(pri.encode())
        pub2 = rsa.PublicKey.load_pkcs1(pub.encode())
        metin = input("Şifrelemek istediğiniz metni giriniz:")
        sifreli_metin = bytes(rsa.encrypt(metin.encode(), pub_key=pub2))
        

        print(f"Şifreli metin:",sifreli_metin)
       
        



def dec(a1, a2):
        if a1 == "b" and a2 == "b":
            print("Daha önce şifreleme yapmadığınız için anahtarınız yok.")
        else:
            p1 = str(a1)
            p2 = a2
            pri_keys = rsa.PrivateKey.load_pkcs1(p2.encode())
        
            try:
            
            
             sifreli_metin = input(":")
            
            
             coz_metin = rsa.decrypt(eval(sifreli_metin), pri_keys)
            
             print("Çözülen metin:", coz_metin)
            except rsa.pkcs1.DecryptionError as e:
                print("Şifre çözme hatası:", e)



if res is not None:
        c, d, r, s = res
    
        if d == pwrm:
            print("[1]Şifrele\n[2]Şifre çöz")
            e = int(input("Yapmak istediğiniz işlemin numarasını giriniz:"))
            if e == 1:
                encry(r, s)
            elif e == 2:
                dec(r, s)
            else:
                print("Doğru giriş yapmadınız.")

        else:
            print("Şifre hatalı")
    
    
else:
        print("Kullanıcı adı bulunamadı.")
      
