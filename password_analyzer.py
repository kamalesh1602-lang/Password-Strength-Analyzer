import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox

# Small educational list. This is not a complete list of weak passwords.
COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty",
    "qwerty123", "admin", "letmein", "welcome", "iloveyou",
    "abc123", "111111", "123123", "password1"
}


def has_predictable_pattern(password):
    """Return True when a password matches a simple predictable pattern."""
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        return True

    if len(password) >= 4 and len(set(password)) == 1:
        return True

    predictable = [
        "0123", "1234", "2345", "3456", "4567",
        "5678", "6789", "abcd", "bcde", "qwer", "asdf"
    ]

    return any(pattern in lower for pattern in predictable)


def analyze_password(password):
    """Check password features and return a score, label and checks."""
    checks = {
        "At least 12 characters": len(password) >= 12,
        "Uppercase letter": any(char.isupper() for char in password),
        "Lowercase letter": any(char.islower() for char in password),
        "Number": any(char.isdigit() for char in password),
        "Special character": any(not char.isalnum() for char in password),
        "No common or predictable pattern":
            bool(password) and not has_predictable_pattern(password)
    }

    score = 0

    if len(password) >= 8:
        score += 15
    if len(password) >= 12:
        score += 15
    if len(password) >= 16:
        score += 10
    if checks["Uppercase letter"]:
        score += 10
    if checks["Lowercase letter"]:
        score += 10
    if checks["Number"]:
        score += 10
    if checks["Special character"]:
        score += 15
    if checks["No common or predictable pattern"]:
        score += 15

    if has_predictable_pattern(password):
        score = min(score, 20)

    if not password:
        score = 0

    if score >= 80:
        label = "Very Strong"
    elif score >= 65:
        label = "Strong"
    elif score >= 45:
        label = "Medium"
    elif score >= 25:
        label = "Weak"
    else:
        label = "Very Weak"

    return score, label, checks


def get_suggestions(password, checks):
    """Create simple suggestions based on the checks."""
    if not password:
        return ["Enter a sample password to see suggestions."]

    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters; longer is generally better.")
    if not checks["Uppercase letter"]:
        suggestions.append("Consider adding an uppercase letter.")
    if not checks["Lowercase letter"]:
        suggestions.append("Consider adding a lowercase letter.")
    if not checks["Number"]:
        suggestions.append("Consider adding a number.")
    if not checks["Special character"]:
        suggestions.append("Consider adding a special character.")
    if not checks["No common or predictable pattern"]:
        suggestions.append("Avoid common passwords, repeated characters and sequences.")

    if not suggestions:
        suggestions.append("Good work. Use a different unique password for every account.")

    return suggestions


def generate_password(length=18):
    """Generate a password using Python's secure secrets module."""
    groups = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        "!@#$%^&*()-_=+?"
    ]

    # Make sure at least one character comes from each group.
    password_chars = [secrets.choice(group) for group in groups]
    all_characters = "".join(groups)

    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_characters))

    # Securely shuffle the characters.
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("650x720")
        self.root.minsize(520, 620)
        self.root.configure(bg="#101827")

        self.password_var = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.generated_password = ""

        self.build_interface()
        self.password_var.trace_add("write", self.update_analysis)

    def build_interface(self):
        title = tk.Label(
            self.root,
            text="Password Strength Analyzer",
            font=("Arial", 22, "bold"),
            fg="white",
            bg="#101827"
        )
        title.pack(pady=(22, 5))

        subtitle = tk.Label(
            self.root,
            text="Check password strength and learn how to improve it.",
            font=("Arial", 11),
            fg="#b8c7dc",
            bg="#101827"
        )
        subtitle.pack(pady=(0, 18))

        card = tk.Frame(self.root, bg="#1b2940", padx=22, pady=18)
        card.pack(fill="both", expand=True, padx=24, pady=8)

        tk.Label(
            card, text="Enter a sample password",
            font=("Arial", 11, "bold"), fg="white", bg="#1b2940"
        ).pack(anchor="w")

        entry_frame = tk.Frame(card, bg="#1b2940")
        entry_frame.pack(fill="x", pady=8)

        self.password_entry = tk.Entry(
            entry_frame,
            textvariable=self.password_var,
            show="*",
            font=("Arial", 13),
            bg="#0d1728",
            fg="white",
            insertbackground="white",
            relief="flat"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=10)

        self.show_button = tk.Button(
            entry_frame, text="Show", command=self.toggle_visibility,
            bg="#344967", fg="white", relief="flat", padx=12
        )
        self.show_button.pack(side="left", padx=(8, 0), ipady=7)

        tk.Label(
            card,
            text="Your password is checked on this computer and is not saved.",
            font=("Arial", 9), fg="#9eb0c9", bg="#1b2940"
        ).pack(anchor="w", pady=(0, 15))

        result_frame = tk.Frame(card, bg="#1b2940")
        result_frame.pack(fill="x")

        tk.Label(
            result_frame, text="Strength:",
            font=("Arial", 11), fg="white", bg="#1b2940"
        ).pack(side="left")

        self.strength_label = tk.Label(
            result_frame, text="Not checked",
            font=("Arial", 11, "bold"), fg="#80b5ff", bg="#1b2940"
        )
        self.strength_label.pack(side="right")

        self.progress = ttk.Progressbar(
            card, maximum=100, length=500, mode="determinate"
        )
        self.progress.pack(fill="x", pady=10)

        self.length_label = tk.Label(
            card, text="0 characters",
            font=("Arial", 9), fg="#9eb0c9", bg="#1b2940"
        )
        self.length_label.pack(anchor="w")

        tk.Label(
            card, text="Security checks",
            font=("Arial", 13, "bold"), fg="white", bg="#1b2940"
        ).pack(anchor="w", pady=(18, 5))

        self.checks_frame = tk.Frame(card, bg="#1b2940")
        self.checks_frame.pack(fill="x", anchor="w")

        self.check_labels = {}
        check_names = [
            "At least 12 characters",
            "Uppercase letter",
            "Lowercase letter",
            "Number",
            "Special character",
            "No common or predictable pattern"
        ]

        for name in check_names:
            label = tk.Label(
                self.checks_frame, text="○  " + name,
                font=("Arial", 10), fg="#ffb0b7", bg="#1b2940"
            )
            label.pack(anchor="w", pady=2)
            self.check_labels[name] = label

        tk.Label(
            card, text="Suggestions",
            font=("Arial", 13, "bold"), fg="white", bg="#1b2940"
        ).pack(anchor="w", pady=(18, 5))

        self.suggestions_box = tk.Listbox(
            card, height=4, font=("Arial", 9),
            bg="#263750", fg="white",
            relief="flat", activestyle="none"
        )
        self.suggestions_box.pack(fill="x")

        button_frame = tk.Frame(card, bg="#1b2940")
        button_frame.pack(fill="x", pady=(18, 8))

        tk.Button(
            button_frame, text="Generate strong password",
            command=self.create_password,
            bg="#347fe5", fg="white", relief="flat", padx=10, pady=9
        ).pack(fill="x", pady=3)

        self.copy_button = tk.Button(
            button_frame, text="Copy generated password",
            command=self.copy_password, state="disabled",
            bg="#344967", fg="white", relief="flat", padx=10, pady=8
        )
        self.copy_button.pack(fill="x", pady=3)

        tk.Button(
            button_frame, text="Clear",
            command=self.clear_password,
            bg="#263750", fg="white", relief="flat", padx=10, pady=8
        ).pack(fill="x", pady=3)

        tk.Label(
            card,
            text=("Tip: Use long, unique passwords and enable multi-factor "
                  "authentication. This score is an educational estimate."),
            wraplength=540, justify="left",
            font=("Arial", 9), fg="#b8c7dc", bg="#1b2940"
        ).pack(anchor="w", pady=(12, 0))

    def toggle_visibility(self):
        if self.show_password.get():
            self.password_entry.config(show="*")
            self.show_password.set(False)
            self.show_button.config(text="Show")
        else:
            self.password_entry.config(show="")
            self.show_password.set(True)
            self.show_button.config(text="Hide")

    def update_analysis(self, *args):
        password = self.password_var.get()
        score, label, checks = analyze_password(password)

        self.strength_label.config(text=label if password else "Not checked")
        self.progress["value"] = score
        self.length_label.config(
            text=f"{len(password)} character(s)"
        )

        for name, passed in checks.items():
            mark = "✓" if passed else "○"
            color = "#7ce0b0" if passed else "#ffb0b7"
            self.check_labels[name].config(
                text=f"{mark}  {name}", fg=color
            )

        self.suggestions_box.delete(0, tk.END)
        for suggestion in get_suggestions(password, checks):
            self.suggestions_box.insert(tk.END, suggestion)

    def create_password(self):
        self.generated_password = generate_password()
        self.password_var.set(self.generated_password)
        self.password_entry.config(show="")
        self.show_password.set(True)
        self.show_button.config(text="Hide")
        self.copy_button.config(state="normal")

    def copy_password(self):
        if not self.generated_password:
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(self.generated_password)
        self.root.update()
        messagebox.showinfo(
            "Copied",
            "Generated password copied to clipboard."
        )

    def clear_password(self):
        self.password_var.set("")
        self.generated_password = ""
        self.password_entry.config(show="*")
        self.show_password.set(False)
        self.show_button.config(text="Show")
        self.copy_button.config(state="disabled")


if __name__ == "__main__":
    window = tk.Tk()
    app = PasswordAnalyzerApp(window)
    window.mainloop()
