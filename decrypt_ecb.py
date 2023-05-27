# Function to convert decimal to binary
def decimal_to_binary(decimal):
    binary = bin(decimal)[2:]  # Remove the '0b' prefix
    return binary.zfill(8)  # Pad with leading zeros to ensure 8-bit representation

# Decimal values for '²', 'starting of heading, SOH', '/', 'space'
decimals = [248, 225, 234, 245]  

# Convert decimal numbers to binary
binaries = [decimal_to_binary(decimal) for decimal in decimals]

# Concatenate binary strings
P1 = binaries[0] + binaries[1]
P2 = binaries[2] + binaries[3]

# Print the results
print("P1:", P1) #1111110100000001
print("P2:", P2) #0010111100100000

nibble_sub_encryp = {
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
def nibble_substitution_encrypt(nibble):
    return nibble_sub_encryp [nibble]

# Nibble substitution lookup table
# DECRYPT
nibble_sub_decrypt = {
    '0000': '1110', 
    '0001': '0011', 
    '0010': '0100', 
    '0011': '1000', 
    '0100': '0001', 
    '0101': '1100', 
    '0110': '1010', 
    '0111': '1111', 
    '1000': '0111',
    '1001': '1101', 
    '1010': '1001', 
    '1011': '0110', 
    '1100': '1011', 
    '1101': '0010',  
    '1110': '0000', 
    '1111': '0101'
}

# Function to perform nibble substitution
def nibble_substitution_decrypt(nibble):
    return nibble_sub_decrypt[nibble]

# Function to perform XOR operation on two binary strings
def xor(binary1, binary2):
    result = ""
    for bit1, bit2 in zip(binary1, binary2):
        result += str(int(bit1) ^ int(bit2))
    return result

# Function to perform shift row operation
def shift_row(row):
    shifted_row = row[0:4] + row[12:16] +  row[8:12]+ row[4:8]
    return shifted_row

def multiply_polynomial(poly1, poly2):
    # Perform polynomial multiplication
    result = 0
    while poly2:
        if poly2 & 1:
            result ^= poly1
        poly1 <<= 1
        if poly1 & 0b10000:
            poly1 ^= 0b10011  # Modulo with x^4 + x + 1
        poly2 >>= 1
    return result

def mix_columns(c0, c1, c2, c3):
    d0 = multiply_polynomial(0b0011, c0) ^ multiply_polynomial(0b0010, c1)
    d1 = multiply_polynomial(0b0010, c0) ^ multiply_polynomial(0b0011, c1)
    d2 = multiply_polynomial(0b0011, c2) ^ multiply_polynomial(0b0010, c3)
    d3 = multiply_polynomial(0b0010, c2) ^ multiply_polynomial(0b0011, c3)
    
    return bin(d0)[2:].zfill(4), bin(d1)[2:].zfill(4), bin(d2)[2:].zfill(4), bin(d3)[2:].zfill(4)

# Function to perform the key generation process
def generate_key(k0):
    # Initial key schedule
    w = [k0[:4], k0[4:8], k0[8:12], k0[12:]]

    # Round constants
    rcon = ['0001', '0010']

    # Generate additional key words
    w.append(xor(xor(w[0], nibble_substitution_encrypt(w[3])), rcon[0]))
    w.append(xor(w[1], w[4]))
    w.append(xor(w[2], w[5]))
    w.append(xor(w[3], w[6]))

    w.append(xor(xor(w[4], nibble_substitution_encrypt(w[7])), rcon[1]))
    w.append(xor(w[5], w[8]))
    w.append(xor(w[6], w[9]))
    w.append(xor(w[7], w[10]))

    # Concatenate key words to form the keys
    k1 = "".join(w[4:8])
    k2 = "".join(w[8:12])

    return k1, k2

# Edit key here!!!!
k0 = "1110000101011001"

# Generate keys
k1, k2 = generate_key(k0)

# Print the results
print("k0:", k0)
print("k1:", k1)
print("k2:", k2)

# Key addition with k2 (P1)
A1 = xor (P1, k2)
print("A1= ",A1)

# shift row - 1st round (P1)
B1 = shift_row((A1[0:4])+(A1[4:8])+(A1[8:12])+(A1[12:16]))
print("B1= ",B1)

# NibbleSub - 1st round (P1)
C1 = nibble_substitution_decrypt(B1[0:4])+nibble_substitution_decrypt(B1[4:8])+nibble_substitution_decrypt(B1[8:12])+nibble_substitution_decrypt(B1[12:16])
print("C1= ",C1)

# Key addition with k1 (P1)
D1 = xor (C1, k1)
print("D1= ",D1)

# Inverse Mix column (P1)
d0 = int(D1[0:4], 2)
d1 = int(D1[4:8], 2)
d2 = int(D1[8:12], 2)
d3 = int(D1[12:16], 2)

e0, e1, e2, e3 = mix_columns(d0, d1, d2,d3)
E1= e0 + e1 + e2 + e3
print("E1= ", E1)

# shift row - 2nd round (P1)
F1 = shift_row((E1[0:4])+(E1[4:8])+(E1[8:12])+(E1[12:16]))
print("F1= ",F1)

# NibbleSub - 2nd round (P1)
G1 = nibble_substitution_decrypt(F1[0:4])+nibble_substitution_decrypt(F1[4:8])+nibble_substitution_decrypt(F1[8:12])+nibble_substitution_decrypt(F1[12:16])
print("G1= ",G1)

# Key addition with k0 (P1)
H1 = xor (G1, k0)
print("H1= ",H1)

# Convert into two 8-bit binary, followed by converting into ASCII CP437
binary_string_1 = H1
ascii_bytes = [int(binary_string_1[i:i+8], 2) for i in range(0, len(binary_string_1), 8)]
ascii_characters = [bytes([byte]).decode('cp437') for byte in ascii_bytes]
plaintext1 = ' '.join(ascii_characters)
print("plaintext1= ",plaintext1)

# Convert into two 8-bit binary, followed by converting into decimal
binary_string = H1
decimal_values = [int(binary_string[i:i+8], 2) for i in range(0, len(binary_string), 8)]
plaintext_dec_1= ' '.join(str(decimal) for decimal in decimal_values)
print(plaintext_dec_1)

## For P2
# Key addition with k2 (P2)
A2 = xor (P2, k2)
print("A2= ",A2)

# shift row - 1st round (P2)
B2 = shift_row((A2[0:4])+(A2[4:8])+(A2[8:12])+(A2[12:16]))
print("B2= ",B2)

# NibbleSub - 1st round (P2)
C2 = nibble_substitution_decrypt(B2[0:4])+nibble_substitution_decrypt(B2[4:8])+nibble_substitution_decrypt(B2[8:12])+nibble_substitution_decrypt(B2[12:16])
print("C2= ",C2)

# Key addition with k1 (P2)
D2 = xor (C2, k1)
print("D2= ",D2)

# Mix column (P2)
d0 = int(D2[0:4], 2)
d1 = int(D2[4:8], 2)
d2 = int(D2[8:12], 2)
d3 = int(D2[12:16], 2)

e0, e1, e2, e3 = mix_columns(d0, d1, d2,d3)
E2= e0 + e1 + e2 + e3
print("E2= ", E2)

# shift row - 2nd round (P2)
F2 = shift_row((E2[0:4])+(E2[4:8])+(E2[8:12])+(E2[12:16]))
print("F2= ",F2)

# InvNibbleSub - 2nd round (P2)
G2 = nibble_substitution_decrypt(F2[0:4])+nibble_substitution_decrypt(F2[4:8])+nibble_substitution_decrypt(F2[8:12])+nibble_substitution_decrypt(F2[12:16])
print("G2= ",G2)

# Key addition with k0 (P2)
H2 = xor (G2, k0)
print("H2= ",H2)

# Convert into two 8-bit binary, followed by converting into ASCII CP437
binary_string_2 = H2
ascii_bytes_2 = [int(binary_string_2[i:i+8], 2) for i in range(0, len(binary_string_2), 8)]
ascii_characters_2 = [bytes([byte]).decode('cp437') for byte in ascii_bytes_2]
plaintext2 = ' '.join(ascii_characters_2)
print("plaintext2= ",plaintext2)

# Convert into two 8-bit binary, followed by converting into decimal
binary_string_2 = H2
decimal_values_2 = [int(binary_string_2[i:i+8], 2) for i in range(0, len(binary_string_2), 8)]
plaintext_dec_2= ' '.join(str(decimal) for decimal in decimal_values_2)
print(plaintext_dec_2)

print("Plaintext: ", plaintext1+" "+plaintext2)
print("Plaintext: ", plaintext_dec_1+" "+plaintext_dec_2)