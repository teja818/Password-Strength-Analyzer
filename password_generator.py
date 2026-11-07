import secrets
import string

WORDS = [
    "amber", "bridge", "cactus", "dolphin", "ember", "forest", "galaxy",
    "harbor", "island", "jungle", "kitten", "lantern", "meadow", "nebula",
    "ocean", "planet", "quartz", "rocket", "sunset", "tiger", "velvet",
    "willow", "xenon", "yellow", "zephyr"
]

def generate_password(length: int = 18) -> str:
    if length < 12:
        raise ValueError("Password length must be at least 12 characters.")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

def generate_passphrase(word_count: int = 4, separator: str = "-") -> str:
    if not 3 <= word_count <= 8:
        raise ValueError("Choose between 3 and 8 words.")
    words = [secrets.choice(WORDS) for _ in range(word_count)]
    # Add a random two-digit suffix to increase variety.
    return separator.join(words) + str(secrets.randbelow(90) + 10)
