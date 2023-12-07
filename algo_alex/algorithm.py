import random
from hashlib import sha256
def a(b):

# Ici fonction a(b) génère une clé secrête d'une chaine aléatoire 'b' composé de chiffre, miniscule, maj, quelques caractères spéciaux) 
    let = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                  'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                  'u', 'v', 'w', 'x', 'y', 'z']

    let_maj = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                  'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                  'U', 'V', 'W', 'X', 'Y', 'Z']

    chre = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    carae = ['&', '#', '@', '$', '%', '.', '?', '!']
    touract = let + let_maj + chre + carae

    x = ''.join(random.choice(touract) for _ in range(b))
    return x

# Ici fontion cnal (x) prend la clé secrete précédente en entrée et effectue une substitution en fonction de leur type (lettre, majuscule, miniscule, chiffre, caractère speciaux) et renvoie la la nouvelle chaine résultante
def cnal (x):
    let = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
                  'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                  'u', 'v', 'w', 'x', 'y', 'z']

    let_maj = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
                  'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                  'U', 'V', 'W', 'X', 'Y', 'Z']

    chre = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    carae = ['&', '#', '@', '$', '%', '.', '?', '!']
    ne = ""

    for s, char in enumerate(x):
        if char in let:
            lise = let
        elif char in let_maj:
            lise = let_maj
        elif char in chre:
            lise = chre
        elif char in carae:
            lise = carae
        else:
            ne += char
            continue
        ince = lise.index(char)
        ne += lise[(ince + len(x) - s) % len(lise)]

    return ne

# Ici fonction hclea (x) prend la chaîne x précédente et la convertit en une représentation hexadécimale à l'aide de la fonction de hachage SHA-256 puis renvoie cette répresentation.
def hclea (x):
    shce = sha256(x.encode('utf-8')).hexdigest()
    return shce
# Ici fonction haclte (ne) reprend la chaîne précédente en enrée et la convertit en une représentation binaire à l'aide de la fonction de hachage SHA-256 puis renvoie cette représentation sous de forme de bytes
def haclte(ne):
    tele = sha256(ne.encode('utf-8')).digest()
    return tele
# Ici cette fonction prend en entrée deux noms de fichiers "ficpt" et "fipt" ainsi que la chaîne "ne". Elle effectue par la suite le chiffrement XOR sur le contenu du fichier source avec la clé dérivée de "ne" et enregistre le résultat dans le fichier de destination.
def chment (ficpt,fipt,ne):
    with open(ficpt, 'rb') as ic_i:
        with open(fipt, 'wb') as fer_o:
            cire = ''.join(format(x, '08b') for x in haclte(ne))
            cte = 0
            while ic_i.peek():
                oct = ord(ic_i.read(1))
                cl = cte % len(haclte(ne))
                cnt = bytes([oct ^ haclte(ne)[cl]])
                fer_o.write(cnt)
                cte = cte + 1

# Ici la fonction prend deux noms de fichiers, "ffre" et "fe" ainsi qu'une chaine "ne".  Elle effectue le déchiffrement XOR du contenu du fichier source avec la même clé dérivée de "ne" utilisée pour le chiffrement et enregistre le résultat dans le fichier de destination.
def det(ffre, fe, ne):
    with open(ffre, 'rb') as ffre:
        with open(fe, 'wb') as fe:
            rey = ''.join(format(x, '08b') for x in haclte(ne))
            coite = 0
            while ffre.peek():
                offre = ord(ffre.read(1))
                caul = coite % len(haclte(ne))
                oaffre = offre ^ haclte(ne)[caul]
                fe.write(bytes([oaffre]))
                coite += 1
x = a(5)
ne = cnal(x)
sh = hclea(x)
print("Sha256 : ", sh)
chment("msg.txt","msg_ch.txt",ne)
det("msg_ch.txt", "msg_dch.txt", ne)                                                                                                                                                                                                            