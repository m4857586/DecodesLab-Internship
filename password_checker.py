def display_heading():
    print("=" * 50)
    print("        PASSWORD STRENGTH CHECKER")
    print("=" * 50)

def get_password():
    password = input("Enter your password: ")
    return password

def check_length(password):
    if len(password) >= 8:
        return True
    else:
        return False

def check_uppercase(password):
    for character in password:
        if character.isupper():
            return True

    return False

def check_lowercase(password):
    for character in password:
        if character.islower():
            return True

    return False

def check_digit(password):
    for character in password:
        if character.isdigit():
            return True

    return False

def check_special_characters(password):
    special_characters = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
    for character in password:
        if character in special_characters:
            return True

    return False

def check_common_password(password):
    common_passwords = ["123456", "password", "123456789", "12345678", "01234567", "qwerty", "abc123", "password123", "admin", "letmein", "welcome", "welcome123", "iloveyou", "admin123", "user123", "login", "guest", "root", "user"]
    if password.lower() in common_passwords:
        return True

    return False


display_heading()
password = get_password()

if password == "":
    print("\nPassword cannot be empty.")
    exit()

if check_common_password(password):
    print("\n⚠ WARNING!")
    print("This is a commonly used password.")
    print("Password Strength: VERY WEAK")
    print("Please choose a more unique password.")
    exit()

score = 0
suggestions = []

if check_length(password):
    score += 1
else:
    suggestions.append(" Add at least 8 characters.")

if check_uppercase(password):
    score += 1
else:
    suggestions.append(" Add at least one uppercase letter.")

if check_lowercase(password):
    score += 1
else:
    suggestions.append(" Add at least one lowercase letter.")

if check_digit(password):
    score += 1
else:
    suggestions.append(" Add at least one digit.")

if check_special_characters(password):
    score += 1
else:
    suggestions.append("Add at least one special character.")

print(f"\nSecurity Score: {score}/5")

if score <= 2:
    print("Password Strength: WEAK")

elif score <= 4:
    print("Password Strength: MEDIUM")

else:
    print("Password Strength: STRONG")

if score == 5:
    print("\nExcellent! Your password meets all security requirements.")
else:
    print("\nSuggestions:")
    for suggestion in suggestions:
        print("-", suggestion)