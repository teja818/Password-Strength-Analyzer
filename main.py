import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from pathlib import Path
from datetime import datetime

from password_analyzer import analyze_password
from password_generator import generate_password, generate_passphrase
from database import save_password_hash, was_password_used, get_history, delete_history, initialize_database

class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer | Cybersecurity Tool")
        self.root.geometry("850x760")
        self.root.minsize(700, 650)
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.length_var = tk.IntVar(value=18)
        self.status_var = tk.StringVar(value="Ready — enter a test password.")
        self.last_result = None
        initialize_database()
        self.build_ui()
        self.analyze()

    def build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text="PASSWORD STRENGTH ANALYZER",
                  font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(header, text="A local Python cybersecurity tool for password assessment",
                  font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        input_frame = ttk.LabelFrame(outer, text="Password assessment", padding=12)
        input_frame.pack(fill="x", pady=6)
        ttk.Label(input_frame, text="Enter a sample password:").pack(anchor="w")
        row = ttk.Frame(input_frame)
        row.pack(fill="x", pady=7)
        self.entry = ttk.Entry(row, textvariable=self.password_var, show="*", font=("Consolas", 12))
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<KeyRelease>", self.analyze)
        ttk.Checkbutton(row, text="Show password", variable=self.show_password_var,
                        command=self.toggle_password).pack(side="left", padx=(10, 0))

        actions = ttk.Frame(input_frame)
        actions.pack(fill="x")
        ttk.Button(actions, text="Analyze", command=self.analyze).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Clear", command=self.clear).pack(side="left", padx=6)
        ttk.Button(actions, text="Check reuse", command=self.check_reuse).pack(side="left", padx=6)
        ttk.Button(actions, text="Save hash to history", command=self.save_to_history).pack(side="left", padx=6)

        result_frame = ttk.LabelFrame(outer, text="Analysis result", padding=12)
        result_frame.pack(fill="x", pady=6)
        top = ttk.Frame(result_frame)
        top.pack(fill="x")
        self.strength_label = ttk.Label(top, text="Not entered", font=("Segoe UI", 16, "bold"))
        self.strength_label.pack(side="left")
        self.score_label = ttk.Label(top, text="Score: 0/9")
        self.score_label.pack(side="right")
        self.progress = ttk.Progressbar(result_frame, maximum=9, mode="determinate")
        self.progress.pack(fill="x", pady=8)
        self.entropy_label = ttk.Label(result_frame, text="Estimated entropy: 0 bits")
        self.entropy_label.pack(anchor="w")
        ttk.Label(result_frame, text="Checks (✓ passed / ✗ needs improvement):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 3))
        self.checks_text = tk.Text(result_frame, height=8, wrap="word", font=("Segoe UI", 9))
        self.checks_text.pack(fill="x")
        self.checks_text.configure(state="disabled")

        suggestion_frame = ttk.LabelFrame(outer, text="Recommendations", padding=12)
        suggestion_frame.pack(fill="x", pady=6)
        self.suggestions_text = tk.Text(suggestion_frame, height=4, wrap="word", font=("Segoe UI", 9))
        self.suggestions_text.pack(fill="x")
        self.suggestions_text.configure(state="disabled")

        generator_frame = ttk.LabelFrame(outer, text="Password generator", padding=12)
        generator_frame.pack(fill="x", pady=6)
        genrow = ttk.Frame(generator_frame)
        genrow.pack(fill="x")
        ttk.Label(genrow, text="Random password length:").pack(side="left")
        ttk.Spinbox(genrow, from_=12, to=64, textvariable=self.length_var, width=5).pack(side="left", padx=8)
        ttk.Button(genrow, text="Generate random password", command=self.generate).pack(side="left", padx=5)
        ttk.Button(genrow, text="Generate passphrase", command=self.generate_phrase).pack(side="left", padx=5)
        ttk.Button(genrow, text="Copy password", command=self.copy_password).pack(side="left", padx=5)

        history_frame = ttk.LabelFrame(outer, text="Local password history", padding=12)
        history_frame.pack(fill="both", expand=True, pady=6)
        hrow = ttk.Frame(history_frame)
        hrow.pack(fill="x", pady=(0, 6))
        ttk.Button(hrow, text="Refresh history", command=self.refresh_history).pack(side="left")
        ttk.Button(hrow, text="Export analysis report", command=self.export_report).pack(side="left", padx=6)
        ttk.Button(hrow, text="Delete all history", command=self.clear_history).pack(side="left", padx=6)
        self.history_tree = ttk.Treeview(history_frame, columns=("label", "date"), show="headings", height=4)
        self.history_tree.heading("label", text="Label")
        self.history_tree.heading("date", text="Saved on")
        self.history_tree.column("label", width=220)
        self.history_tree.column("date", width=180)
        self.history_tree.pack(fill="both", expand=True)
        ttk.Label(outer, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", pady=(8, 0))
        ttk.Label(outer,
                  text="Privacy: passwords are not stored in plaintext. History is local to this project folder. Use test passwords, not real account credentials.",
                  wraplength=800, foreground="#555").pack(anchor="w", pady=(7, 0))
        self.refresh_history()

    def toggle_password(self):
        self.entry.config(show="" if self.show_password_var.get() else "*")

    def set_text(self, widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def analyze(self, event=None):
        password = self.password_var.get()
        result = analyze_password(password)
        self.last_result = result
        self.strength_label.config(text=result["strength"])
        self.score_label.config(text=f"Score: {result['score']}/9")
        self.progress["value"] = result["score"]
        self.entropy_label.config(
            text=f"Estimated entropy: {result['entropy']} bits (rough estimate, not a security guarantee)"
        )
        checks = "\n".join(f"{'✓' if ok else '✗'}  {label}" for label, ok in result["checks"])
        self.set_text(self.checks_text, checks or "Enter a password to see security checks.")
        self.set_text(self.suggestions_text, "\n".join("• " + s for s in result["suggestions"]))
        self.status_var.set("Analysis updated." if password else "Ready — enter a test password.")

    def clear(self):
        self.password_var.set("")
        self.analyze()
        self.entry.focus_set()

    def generate(self):
        try:
            password = generate_password(int(self.length_var.get()))
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Invalid length", str(exc))
            return
        self.password_var.set(password)
        self.show_password_var.set(True)
        self.toggle_password()
        self.analyze()
        self.copy_to_clipboard(password)
        self.status_var.set("Random password generated and copied to clipboard.")

    def generate_phrase(self):
        phrase = generate_passphrase(4, "-")
        self.password_var.set(phrase)
        self.show_password_var.set(True)
        self.toggle_password()
        self.analyze()
        self.copy_to_clipboard(phrase)
        self.status_var.set("Passphrase generated and copied to clipboard.")

    def copy_to_clipboard(self, value):
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()

    def copy_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("No password", "Enter or generate a password first.")
            return
        self.copy_to_clipboard(password)
        self.status_var.set("Password copied to clipboard. Clear your clipboard when finished.")

    def check_reuse(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Missing password", "Enter a test password first.")
        elif was_password_used(password):
            messagebox.showwarning("Password reused", "This password matches an entry in this app's local history.")
        else:
            messagebox.showinfo("No match", "No match found in this app's local history.")
        self.refresh_history()

    def save_to_history(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Missing password", "Enter a test password first.")
            return
        if was_password_used(password):
            messagebox.showwarning("Already saved", "This password already exists in local history.")
            return
        label = simpledialog.askstring("Password label", "Enter a label (e.g., Demo account):", parent=self.root)
        if label is None:
            return
        save_password_hash(password, label)
        self.refresh_history()
        self.status_var.set("Salted password hash saved locally.")
        messagebox.showinfo("Saved", "Only a salted PBKDF2 hash was saved, not the plaintext password.")

    def refresh_history(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        for _id, label, created_at in get_history():
            self.history_tree.insert("", "end", values=(label, created_at))

    def clear_history(self):
        if not messagebox.askyesno("Confirm deletion", "Delete all saved password-history entries?"):
            return
        delete_history()
        self.refresh_history()
        self.status_var.set("Local password history cleared.")

    def export_report(self):
        if not self.password_var.get():
            messagebox.showwarning("No analysis", "Enter a sample password before exporting.")
            return
        result = analyze_password(self.password_var.get())
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text report", "*.txt")],
            initialfile="password_analysis_report.txt"
        )
        if not path:
            return
        # Do not include the password itself in the exported report.
        lines = [
            "PASSWORD STRENGTH ANALYSIS REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Strength: {result['strength']}",
            f"Score: {result['score']}/9",
            f"Password length: {len(self.password_var.get())} characters",
            f"Estimated entropy: {result['entropy']} bits",
            "",
            "SECURITY CHECKS:"
        ]
        lines.extend(f"{'PASS' if ok else 'REVIEW'} - {label}" for label, ok in result["checks"])
        lines += ["", "RECOMMENDATIONS:"]
        lines.extend(f"- {s}" for s in result["suggestions"])
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        messagebox.showinfo("Report exported", f"Report saved to:\n{path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()
