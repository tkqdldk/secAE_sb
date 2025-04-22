# Documentation du Code AES et DES

## Documentation du module AES (aes.py)

Le module `aes.py` fournit une implémentation de l'algorithme de chiffrement AES (Advanced Encryption Standard). Cette documentation détaille les fonctions et méthodes principales du code.

### Fonctions de conversion

#### `text2matrix(text)`
- **Objectif**: Convertit un nombre entier (représentant des données) en une matrice 4×4 utilisée par AES
- **Paramètre**: `text` - Nombre entier représentant les données à chiffrer/déchiffrer
- **Retour**: Une matrice 4×4 où chaque élément est un octet

#### `matrix2text(matrix)`
- **Objectif**: Convertit une matrice 4×4 en un nombre entier
- **Paramètre**: `matrix` - Matrice 4×4 d'octets
- **Retour**: Nombre entier représentant les données

### Classe `AES`

#### Initialisation
```python
def __init__(self, master_key):
    self.change_key(master_key)
```
- **Paramètre**: `master_key` - Clé principale pour le chiffrement

#### `change_key(master_key)`
- **Objectif**: Génère les sous-clés de round à partir de la clé principale
- **Paramètre**: `master_key` - Clé principale pour le chiffrement

#### `encrypt(plaintext)`
- **Objectif**: Chiffre les données en texte clair
- **Paramètre**: `plaintext` - Données à chiffrer (sous forme d'entier)
- **Retour**: Données chiffrées (sous forme d'entier)

#### `decrypt(ciphertext)`
- **Objectif**: Déchiffre les données chiffrées
- **Paramètre**: `ciphertext` - Données chiffrées (sous forme d'entier)
- **Retour**: Données déchiffrées (sous forme d'entier)

#### Méthodes d'opérations AES internes
- `__add_round_key(s, k)`: Effectue l'opération XOR entre l'état et la clé de round
- `__round_encrypt(state_matrix, key_matrix)`: Exécute un round complet du chiffrement AES
- `__round_decrypt(state_matrix, key_matrix)`: Exécute un round complet du déchiffrement AES
- `__sub_bytes(s)`: Remplace chaque octet par sa valeur correspondante dans la S-box
- `__inv_sub_bytes(s)`: Opération inverse de SubBytes pour le déchiffrement
- `__shift_rows(s)`: Décale cycliquement les lignes de la matrice d'état
- `__inv_shift_rows(s)`: Opération inverse de ShiftRows pour le déchiffrement
- `__mix_columns(s)`: Multiplie chaque colonne par une matrice constante
- `__inv_mix_columns(s)`: Opération inverse de MixColumns pour le déchiffrement
- `__mix_single_column(a)`: Applique MixColumns à une seule colonne

## Documentation du module DES (des_module.py)

Le module `des_module.py` fournit une implémentation des algorithmes DES (Data Encryption Standard) et Triple DES. Cette documentation détaille les classes et méthodes principales du code.

### Constantes
- `ECB = 0`: Mode Electronic Codebook
- `CBC = 1`: Mode Cipher Block Chaining
- `PAD_NORMAL = 1`: Mode de padding normal
- `PAD_PKCS5 = 2`: Mode de padding PKCS#5

### Classe de base `_baseDes`

#### Initialisation
```python
def __init__(self, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL)
```
- **Paramètres**:
  - `mode`: Mode de chiffrement (ECB ou CBC)
  - `IV`: Vecteur d'initialisation pour le mode CBC
  - `pad`: Caractère de remplissage
  - `padmode`: Mode de padding

#### Méthodes principales
- Getters/Setters pour la clé, le mode, le padding, et le vecteur d'initialisation
- `_padData(data, pad, padmode)`: Ajoute du padding aux données
- `_unpadData(data, pad, padmode)`: Retire le padding des données
- `_guardAgainstUnicode(data)`: Assure la compatibilité entre Python 2 et 3

### Classe `des` (hérite de `_baseDes`)

#### Initialisation
```python
def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL)
```
- **Paramètres**:
  - `key`: Clé de chiffrement de 8 octets

#### Constantes
- `ENCRYPT = 0x00`: Mode chiffrement
- `DECRYPT = 0x01`: Mode déchiffrement

#### Méthodes principales
- `setKey(key)`: Définit la clé et génère les sous-clés
- `encrypt(data, pad=None, padmode=None)`: Chiffre les données
- `decrypt(data, pad=None, padmode=None)`: Déchiffre les données

#### Méthodes internes
- `__String_to_BitList(data)`: Convertit une chaîne en liste de bits
- `__BitList_to_String(data)`: Convertit une liste de bits en chaîne
- `__permutate(table, block)`: Effectue une permutation selon une table
- `__create_sub_keys()`: Génère les sous-clés pour chaque round
- `__des_crypt(block, crypt_type)`: Exécute l'algorithme DES sur un bloc
- `crypt(data, crypt_type)`: Interface principale pour le chiffrement/déchiffrement

### Classe `triple_des` (hérite de `_baseDes`)

#### Initialisation
```python
def __init__(self, key, mode=ECB, IV=None, pad=None, padmode=PAD_NORMAL)
```
- **Paramètres**:
  - `key`: Clé de chiffrement de 16 ou 24 octets

#### Méthodes principales
- `setKey(key)`: Configure les trois instances DES avec les clés appropriées
- `encrypt(data, pad=None, padmode=None)`: Chiffre les données avec Triple DES
- `decrypt(data, pad=None, padmode=None)`: Déchiffre les données avec Triple DES

### Points techniques importants

1. La taille de bloc est fixée à 8 octets (64 bits) pour DES et Triple DES
2. La classe `triple_des` utilise trois instances de `des` pour implémenter l'algorithme
3. En mode CBC, le vecteur d'initialisation doit être de la même taille que le bloc
4. Pour le Triple DES, si une clé de 16 octets est fournie, la troisième clé est identique à la première
