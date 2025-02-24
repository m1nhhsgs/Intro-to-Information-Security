class PlayfairCipher:
    def __init__(self, key):
        self.key_matrix = [['' for _ in range(5)] for _ in range(5)]
        self.generate_key_matrix(key)

    def generate_key_matrix(self, key):
        # Initialize array to mark used letters
        present = [False] * 26
        x, y = 0, 0

        # First fill the key
        for char in key.upper():
            if char == 'J':
                char = 'I'
            if not present[ord(char) - ord('A')]:
                self.key_matrix[x][y] = char
                present[ord(char) - ord('A')] = True
                y += 1
                if y == 5:
                    x += 1
                    y = 0

        # Fill remaining characters
        for char in [chr(i) for i in range(ord('A'), ord('Z') + 1)]:
            if char == 'J':
                continue
            if not present[ord(char) - ord('A')]:
                self.key_matrix[x][y] = char
                present[ord(char) - ord('A')] = True
                y += 1
                if y == 5:
                    x += 1
                    y = 0

    def find_position(self, char):
        if char == 'J':
            char = 'I'
        for i in range(5):
            for j in range(5):
                if self.key_matrix[i][j] == char:
                    return i, j
        return -1, -1

    def prepare_text(self, text):
        # Remove non-alphabetic characters and convert J to I
        text = ''.join(c if c != 'J' else 'I' for c in text.upper() if c.isalpha())
        
        # Handle duplicate letters and odd length
        result = []
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                result.append(text[i] + 'X')
                break
            if text[i] == text[i + 1]:
                result.append(text[i] + 'X')
                i += 1
            else:
                result.append(text[i] + text[i + 1])
                i += 2
                
        return ''.join(result)

    def encrypt(self, text):
        text = self.prepare_text(text)
        cipher = []

        for i in range(0, len(text), 2):
            r1, c1 = self.find_position(text[i])
            r2, c2 = self.find_position(text[i + 1])

            if r1 == r2:  # Same row
                cipher.append(self.key_matrix[r1][(c1 + 1) % 5])
                cipher.append(self.key_matrix[r2][(c2 + 1) % 5])
            elif c1 == c2:  # Same column
                cipher.append(self.key_matrix[(r1 + 1) % 5][c1])
                cipher.append(self.key_matrix[(r2 + 1) % 5][c2])
            else:  # Rectangle case
                cipher.append(self.key_matrix[r1][c2])
                cipher.append(self.key_matrix[r2][c1])

        return ''.join(cipher)

    def print_key_matrix(self):
        for row in self.key_matrix:
            print(' '.join(row))

def main():
    # key = input("Enter key: ")
    # plaintext = input("Enter plaintext: ")
    key = "KEYWORD"
    plaintext = "WELCOME"

    cipher = PlayfairCipher(key)

    print("\nKey Matrix:")
    cipher.print_key_matrix()

    encrypted_text = cipher.encrypt(plaintext)
    print(f"\nEncrypted Text: {encrypted_text}")

if __name__ == "__main__":
    main()