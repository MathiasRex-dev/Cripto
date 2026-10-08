from crypto import decrypt_vigenere

# def score_text(text, dictionary):
#     words = text.upper().split()
#     if not words:
#         return 0
#     valid_count = sum(1 for word in words if word in dictionary)
#     return valid_count / len(words)

def score_text(text, dictionary=None):
    common_trigrams = [
        "THE", "AND", "ING", "HER", "HAT", "HIS", "THA", "ERE", "FOR",
        "ENT", "ION", "TER", "WAS", "YOU", "ITH", "VER", "ALL", "WIT"
    ]
    
    score = 0
    for tri in common_trigrams:
        score += text.count(tri)
        
    return score

def decrypt_vigenere_codebreaker(ciphertext, possible_keys, dictionary):
    
    best_key = None
    best_score = -1
    best_plaintext = ""

    for key in possible_keys:
        plaintext = decrypt_vigenere(ciphertext, key)
        score = score_text(plaintext, dictionary)

        if score > best_score:
            best_score = score
            best_key = key  
            best_plaintext = plaintext

    return best_key, best_plaintext
