
Certainly! Below is a Python script that assesses the strength of a password based on its length, the presence of uppercase and lowercase letters, numbers, and special characters. The script provides feedback to the user about the password's strength.

python
Copy code
import re

def assess_password_strength(password):
    # Initialize criteria flags
    length_criteria = len(password) >= 8
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    number_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[\W_]', password) is not None

    # Count how many criteria are met
    criteria_met = sum([length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria])

    # Determine strength based on criteria met
    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Moderate"
    elif criteria_met == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Generate feedback
    feedback = {
        'Length Criteria (>=8 characters)': length_criteria,
        'Uppercase Letter': uppercase_criteria,
        'Lowercase Letter': lowercase_criteria,
        'Number': number_criteria,
        'Special Character': special_char_criteria,
    }

    return strength, feedback

# Example usage
password = input("Enter a password to assess its strength: ")
strength, feedback = assess_password_strength(password)

print("\nPassword Strength: ", strength)
print("\nCriteria Feedback:")
for criterion, met in feedback.items():
    print(f"{criterion}: {'Met' if met else 'Not Met'}")
Explanation:
Criteria Checks:

length_criteria: Checks if the password length is at least 8 characters.
uppercase_criteria: Checks for the presence of at least one uppercase letter.
lowercase_criteria: Checks for the presence of at least one lowercase letter.
number_criteria: Checks for the presence of at least one number.
special_char_criteria: Checks for the presence of at least one special character.
Criteria Met Count:

The criteria_met variable counts how many of the criteria the password meets.
Strength Determination:

Based on the number of criteria met, the script classifies the password as "Very Strong", "Strong", "Moderate", "Weak", or "Very Weak".
Feedback:

Provides specific feedback on which criteria are met or not met.
You can run this script in a Python environment, and it will prompt you to enter a password. It will then assess and provide feedback on its strength.




