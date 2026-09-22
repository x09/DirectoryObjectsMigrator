"""
Password generation utilities
"""
import secrets
import string


class PasswordGenerator:
    """Generate random passwords for user accounts"""

    DEFAULT_LENGTH = 12
    DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

    @staticmethod
    def generate(length: int = DEFAULT_LENGTH, charset: str = None) -> str:
        """
        Generate a cryptographically secure random password

        Args:
            length: Password length (default 12)
            charset: Character set to use (default: alphanumeric + underscore + hyphen)

        Returns:
            Random password string
        """
        if charset is None:
            charset = PasswordGenerator.DEFAULT_CHARSET

        if length < 1:
            raise ValueError("Password length must be at least 1")

        if not charset:
            raise ValueError("Charset cannot be empty")

        # Use secrets module for cryptographically strong random generation
        password = ''.join(secrets.choice(charset) for _ in range(length))

        return password

    @staticmethod
    def generate_batch(count: int, length: int = DEFAULT_LENGTH, charset: str = None) -> list:
        """
        Generate multiple unique passwords

        Args:
            count: Number of passwords to generate
            length: Password length
            charset: Character set

        Returns:
            List of unique password strings
        """
        passwords = set()

        while len(passwords) < count:
            passwords.add(PasswordGenerator.generate(length, charset))

        return list(passwords)

    @staticmethod
    def validate_charset(charset: str) -> bool:
        """
        Validate that a charset is suitable for password generation

        Args:
            charset: Character set string

        Returns:
            True if valid, False otherwise
        """
        if not charset or len(charset) < 4:
            return False

        # Check for duplicates
        if len(set(charset)) != len(charset):
            return False

        return True

    @staticmethod
    def get_strength(password: str) -> dict:
        """
        Estimate password strength

        Args:
            password: Password to analyze

        Returns:
            Dict with strength metrics
        """
        if not password:
            return {
                'length': 0,
                'has_lowercase': False,
                'has_uppercase': False,
                'has_digits': False,
                'has_special': False,
                'strength': 'empty',
                'score': 0
            }

        has_lowercase = any(c.islower() for c in password)
        has_uppercase = any(c.isupper() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(c in '_-!@#$%^&*(),.?":{}|<>' for c in password)

        score = 0
        score += len(password) * 4
        if has_lowercase:
            score += 10
        if has_uppercase:
            score += 10
        if has_digits:
            score += 10
        if has_special:
            score += 20

        if score < 40:
            strength = 'weak'
        elif score < 70:
            strength = 'medium'
        elif score < 100:
            strength = 'strong'
        else:
            strength = 'very_strong'

        return {
            'length': len(password),
            'has_lowercase': has_lowercase,
            'has_uppercase': has_uppercase,
            'has_digits': has_digits,
            'has_special': has_special,
            'strength': strength,
            'score': score
        }


if __name__ == "__main__":
    # Self-test
    print("=== Password Generator Test ===\n")

    # Generate single password
    pwd = PasswordGenerator.generate()
    print(f"Random password (default): {pwd}")
    print(f"Strength: {PasswordGenerator.get_strength(pwd)}\n")

    # Generate custom length
    pwd = PasswordGenerator.generate(length=16)
    print(f"Random password (16 chars): {pwd}")
    print(f"Strength: {PasswordGenerator.get_strength(pwd)}\n")

    # Generate with custom charset
    pwd = PasswordGenerator.generate(length=8, charset=string.ascii_uppercase + string.digits)
    print(f"Random password (uppercase + digits): {pwd}")
    print(f"Strength: {PasswordGenerator.get_strength(pwd)}\n")

    # Generate batch
    batch = PasswordGenerator.generate_batch(5)
    print(f"Batch of 5 passwords:")
    for i, p in enumerate(batch, 1):
        print(f"  {i}. {p}")
