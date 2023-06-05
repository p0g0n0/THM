def responsabilidade(x):
    if x == "pato" or x == "duck" or x == "durck" or x == "pauto" or x == "marina" or x == "mari":
        return "não é responsável"
    else:
        return "é responsável"
    
x = input("Diga o nome da espécie:\n-> ")

print(f"{x} {responsabilidade(x)}")