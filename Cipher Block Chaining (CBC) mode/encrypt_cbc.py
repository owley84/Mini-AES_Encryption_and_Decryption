# Function to convert character to binary
def char_to_binary(char):
    binary = format(ord(char), '08b')
    return binary

# Main program
plaintext = "lame"

# Convert characters to binary
b1 = char_to_binary(plaintext[0])
b2 = char_to_binary(plaintext[1])
b3 = char_to_binary(plaintext[2])
b4 = char_to_binary(plaintext[3])

# Concatenate binary strings
P1 = b1 + b2
P2 = b3 + b4

# Print the results
print("P1:", P1)
print("P2:", P2)

# Nibble substitution lookup table
nibble_sub = {
    '0000': '1110',
    '0001': '0100',
    '0010': '1101',
    '0011': '0001',
    '0100': '0010',
    '0101': '1111',
    '0110': '1011',
    '0111': '1000',
    '1000': '0011',
    '1001': '1010',
    '1010': '0110',
    '1011': '1100',
    '1100': '0101',
    '1101': '1001',
    '1110': '0000',
    '1111': '0111'
}

# Function to perform nibble substitution
def nibble_substitution(nibble):
    return nibble_sub[nibble]

# Function to perform XOR operation on two binary strings
def xor(binary1, binary2):
    result = ""
    for bit1, bit2 in zip(binary1, binary2):
        result += str(int(bit1) ^ int(bit2))
    return result

# Function to perform shift row operation
def shift_row(row):
    shifted_row = row[0:4] + row[12:16] + row[8:12] + row[4:8]
    return shifted_row

# Function Mix Column
def multiply_polynomial(poly1, poly2):
    # Perform polynomial multiplication
    result = 0
    while poly2:
        if poly2 & 1:
            result ^= poly1
        poly1 <<= 1
        if poly1 & 0b10000:
            poly1 ^= 0b10011 # xor with x^4 + x + 1
        poly2 >>= 1
    return result

def mix_columns(c0, c1, c2, c3):
    d0 = multiply_polynomial(0b0011, c0) ^ multiply_polynomial(0b0010, c1)
    d1 = multiply_polynomial(0b0010, c0) ^ multiply_polynomial(0b0011, c1)
    d2 = multiply_polynomial(0b0011, c2) ^ multiply_polynomial(0b0010, c3)
    d3 = multiply_polynomial(0b0010, c2) ^ multiply_polynomial(0b0011, c3)
    
    return bin(d0)[2:].zfill(4), bin(d1)[2:].zfill(4), bin(d2)[2:].zfill(4), bin(d3)[2:].zfill(4)

# Initialization vector (VI)
VI = "1110001110100001"

# Function to perform the key generation process
def generate_key(k0):
    # Initial key schedule
    w = [k0[:4], k0[4:8], k0[8:12], k0[12:]]

    # Round constants
    rcon = ['0001', '0010']

    # Generate additional key words
    w.append(xor(xor(w[0], nibble_substitution(w[3])), rcon[0]))
    w.append(xor(w[1], w[4]))
    w.append(xor(w[2], w[5]))
    w.append(xor(w[3], w[6]))

    w.append(xor(xor(w[4], nibble_substitution(w[7])), rcon[1]))
    w.append(xor(w[5], w[8]))
    w.append(xor(w[6], w[9]))
    w.append(xor(w[7], w[10]))

    # Concatenate key words to form the keys
    k1 = "".join(w[4:8])
    k2 = "".join(w[8:12])

    return k1, k2

# Main program
k0 = "1110000101011001"

# Generate keys
k1, k2 = generate_key(k0)

# Print the results
print("k0:", k0)
print("k1:", k1)
print("k2:", k2)

## For P1
# Key addition with initialization vector (IV)
X1 = xor(P1, VI)
print("X1= ", X1)

# Key addition with k0 (P1)
A1 = xor (X1, k0)
print("A1= ",A1)

# NibbleSub - 1st round (P1)
B1 = nibble_substitution(A1[0:4])+nibble_substitution(A1[4:8])+nibble_substitution(A1[8:12])+nibble_substitution(A1[12:16])
print("B1= ",B1)

# shift row - 1st round (P1)
C1 = shift_row((B1[0:4])+(B1[4:8])+(B1[8:12])+(B1[12:16]))
print("C1= ",C1)

# Mix column (P1)

c0 = int(C1[0:4], 2)
c1 = int(C1[4:8], 2)
c2 = int(C1[8:12], 2)
c3 = int(C1[12:16], 2)

d0, d1, d2, d3 = mix_columns(c0, c1, c2, c3)
D1= d0 + d1 + d2 + d3
print("D1= ", D1)

# Key addition with k1 (P1)
E1 = xor (D1, k1)
print("E1= ",E1)

# NibbleSub - 2nd round (P1)
F1 = nibble_substitution(E1[0:4])+nibble_substitution(E1[4:8])+nibble_substitution(E1[8:12])+nibble_substitution(E1[12:16])
print("F1= ",F1)

# shift row - 2nd round (P1)
G1 = shift_row((F1[0:4])+(F1[4:8])+(F1[8:12])+(F1[12:16]))
print("G1= ",G1)

# Key addition with k2 (P1)
H1 = xor (G1, k2)
print("H1= ",H1)

# Convert into two 8-bit binary, followed by converting into ASCII CP437
binary_string_1 = H1
ascii_bytes = [int(binary_string_1[i:i+8], 2) for i in range(0, len(binary_string_1), 8)]
ascii_characters = [bytes([byte]).decode('cp437') for byte in ascii_bytes]
cipher1 = ' '.join(ascii_characters)
print("cipher1= ",cipher1)

# Convert into two 8-bit binary, followed by converting into decimal
binary_string = H1
decimal_values = [int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8)]
cipher_dec_1= ' '.join(str(decimal) for decimal in decimal_values)
print(cipher_dec_1)

## For P2
# Key addition with initialization vector (IV)
X2 = xor(P2, H1)
print("X2= ", X2)

# Key addition with k0 (P2)
A2 = xor (X2, k0)
print("A2= ",A2)

# NibbleSub - 1st round (P2)
B2 = nibble_substitution(A2[0:4])+nibble_substitution(A2[4:8])+nibble_substitution(A2[8:12])+nibble_substitution(A2[12:16])
print("B2= ",B2)

# shift row - 1st round (P2)
C2 = shift_row((B2[0:4])+(B2[4:8])+(B2[8:12])+(B2[12:16]))
print("C2= ",C2)

# Mix column (P2)

c0 = int(C2[0:4], 2)
c1 = int(C2[4:8], 2)
c2 = int(C2[8:12], 2)
c3 = int(C2[12:16], 2)

d0, d1, d2, d3 = mix_columns(c0, c1, c2, c3)
D2= d0 + d1 + d2 + d3
print("D2= ", D2)

# Key addition with k1 (P2)
E2 = xor (D2, k1)
print("E2= ",E2)

# NibbleSub - 2nd round (P2)
F2 = nibble_substitution(E2[0:4])+nibble_substitution(E2[4:8])+nibble_substitution(E2[8:12])+nibble_substitution(E2[12:16])
print("F2= ",F2)

# shift row - 2nd round (P2)
G2 = shift_row((F2[0:4])+(F2[4:8])+(F2[8:12])+(F2[12:16]))
print("G2= ",G2)

# Key addition with k2 (P1)
H2 = xor (G2, k2)
print("H2= ",H2)

# Convert into two 8-bit binary, followed by converting into ASCII CP437
binary_string_2 = H2
ascii_bytes = [int(binary_string_2[i:i+8], 2) for i in range(0, len(binary_string_2), 8)]
ascii_characters = [bytes([byte]).decode('cp437') for byte in ascii_bytes]
cipher2 = ' '.join(ascii_characters)
print("cipher2= ",cipher2)

# Convert into two 8-bit binary, followed by converting into decimal
binary_string = H2
decimal_values = [int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8)]
cipher_dec_2= ' '.join(str(decimal) for decimal in decimal_values)
print(cipher_dec_2)

print("Ciphertext: ", cipher1+" "+cipher2)
print("Ciphertext_dec: ", cipher_dec_1+" "+cipher_dec_2)