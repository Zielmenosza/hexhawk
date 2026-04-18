# hexhawk_assistant.py
# HexHawk Companion Assistant

import os
import json
import subprocess
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk
from datetime import datetime
import pyperclip
import traceback
import sys

PROJECT_PATH = r"D:\Project\HexHawk"
LOG_FILE     = os.path.join(PROJECT_PATH, "logs", "assistant_output.log")
TASKS_FILE   = os.path.join(PROJECT_PATH, "logs", "task_planner.json")
HISTORY_FILE = os.path.join(PROJECT_PATH, "logs", "prompt_history.json")
PLUGINS_DIR  = os.path.join(PROJECT_PATH, "plugins")

os.makedirs(os.path.join(PROJECT_PATH, "logs"),    exist_ok=True)
os.makedirs(os.path.join(PROJECT_PATH, "plugins"), exist_ok=True)

# Static help content
HELP_CONTENT = {
    "Getting Started": "Welcome to HexHawk Assistant! Use the top buttons to manage tasks, plugins, logs, and generate prompts.",
    "Toolchain Check": "Verifies if Rust, Cargo, Node.js, npm, and Git are installed correctly. Use this if commands fail or builds break.",
    "Logs & Debugging": "Displays logs live from assistant_output.log. Filter using keywords like 'panic', 'error', 'failed'.",
    "Plugin Generator": "Creates a new Rust plugin folder with a starter lib.rs. Add your parsing logic there.",
    "Task Planner": "Track development tasks or bugs. You can save/load tasks to keep progress across sessions.",
    "Common Errors": "PowerShell errors? Run as Admin.\nPython module missing? Try: pip install pyperclip\ntauri not found? Run: cargo install tauri-cli"
}

class AssistantApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HexHawk Assistant")
        self.root.geometry("1200x800")
        self.filter_keyword = tk.StringVar()

        # ── Splash Screen ────────────────────────────────────────────────
        self.splash = tk.Toplevel(self.root)
        self.splash.title("Starting HexHawk Assistant")
        self.splash.geometry("400x140")
        self.splash.transient(self.root)
        self.splash.grab_set()
        self.splash.resizable(False, False)

        tk.Label(self.splash, text="HexHawk Assistant (Beta)", font=("Segoe UI", 14, "bold")).pack(pady=10)

        self.status_label = tk.Label(self.splash, text="Initializing...", font=("Segoe UI", 11))
        self.status_label.pack(pady=5)

        self.progress = ttk.Progressbar(self.splash, orient="horizontal", length=320, mode="determinate")
        self.progress.pack(pady=10)
        self.progress["value"] = 0
        self.splash.update()

        self._update_progress(10, "Checking paths...")

        # ── Create UI widgets BEFORE loading content ─────────────────────
        self._update_progress(25, "Creating log viewer...")

        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        filter_frame = tk.Frame(self.root)
        filter_frame.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        tk.Entry(filter_frame, textvariable=self.filter_keyword, width=40).pack(side=tk.LEFT, padx=6)

        self._update_progress(45, "Building button bar...")
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(fill=tk.X, padx=4, pady=4)

        buttons = [
            ("Check Toolchain",   self.check_toolchain,   "Verifies Rust, Node, Git, npm"),
            ("Run Tauri Dev",     self.run_tauri_dev,     "Runs frontend/backend dev mode"),
            ("Plugin Generator",  self.generate_plugin,   "Create a new Rust plugin"),
            ("Task Planner",      self.open_task_planner, "Add, save, and load tasks"),
            ("Prompt Builder",    self.build_prompt,      "Build prompt using logs"),
            ("Help",              self.show_help,         "Open help tabs"),
            ("Filter Logs",       self.apply_log_filter,  "Filter log view"),
            ("Clear",             self.clear_log_output,  "Clear log view"),
            ("Gen Code Prompt",   self.generate_code_snippet, "Generate code prompt for Grok/ChatGPT"),
            ("Write Code File",   self.write_code_file,   "Generate & write code directly to file"),
        ]

        for label, cmd, tip in buttons:
            self.create_button(label, cmd, tip)

        self._update_progress(70, "Loading logs...")
        self.load_logs()

        self._update_progress(85, "Preparing history...")
        if not os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)

        self._update_progress(100, "Ready!")
        self.splash.destroy()

    def _update_progress(self, value: int, text: str):
        self.progress["value"] = value
        self.status_label.config(text=text)
        self.splash.update()

    def create_button(self, label, command, tooltip=""):
        btn = tk.Button(self.button_frame, text=label, command=command, width=14)
        btn.pack(side=tk.LEFT, padx=3)
        if tooltip:
            def enter(e): self.root.title(f"{label} – {tooltip}")
            def leave(e): self.root.title("HexHawk Assistant")
            btn.bind("<Enter>", enter)
            btn.bind("<Leave>", leave)

    # ── Generate Code Snippet Prompt ────────────────────────────────────
    def generate_code_snippet(self):
        description = simpledialog.askstring("Generate Code", "What code do you want to generate?\n(e.g. 'Tauri command get_available_plugins')")
        if not description:
            return

        context = simpledialog.askstring("Optional Context", "Paste any existing code or details (optional):", initialvalue="")

        prompt = f"""
Help me implement this in HexHawk (Tauri + Rust + React reverse engineering tool):

Description: {description}

Optional context: {context or 'None provided'}

Provide:
- Full code block(s)
- File name(s) and where to paste
- How to test it
- Any npm/cargo installs needed
Be step-by-step for a beginner.
"""

        pyperclip.copy(prompt)
        messagebox.showinfo("Prompt Copied", "Code generation prompt copied to clipboard!\nPaste it to Grok/ChatGPT now.")

        self.log_text.insert(tk.END, f"\nGenerated code prompt: {description}\n")
        self.log_text.see(tk.END)

    # ── Write Code File (Option 3) ──────────────────────────────────────
    def write_code_file(self):
        # Step 1: Ask what to generate
        description = simpledialog.askstring("Write Code File", "What code do you want to generate and write?\n(e.g. 'Rust plugin for string extraction')")
        if not description:
            return

        # Step 2: Ask for file path (relative to project)
        relative_path = simpledialog.askstring("File Path", "Where to save the file?\n(e.g. 'src-tauri/src/plugins/strings.rs')")
        if not relative_path:
            return

        full_path = os.path.join(PROJECT_PATH, relative_path.replace('/', os.path.sep))  # handle / or \

        # Step 3: Optional context
        context = simpledialog.askstring("Optional Context", "Paste any existing code or details (optional):", initialvalue="")

        # Step 4: Build prompt for Grok/ChatGPT
        prompt = f"""
Generate complete code for this in HexHawk (Tauri + Rust + React tool):

Description: {description}

Optional context: {context or 'None'}

Provide ONLY the code block – no explanations.
Make it ready to write to file: {relative_path}
"""

        pyperclip.copy(prompt)
        messagebox.showinfo("Prompt Copied", "Paste this to Grok/ChatGPT to get the code.\nThen paste the code back here in the next dialog.")

        # Step 5: Ask for the generated code (you paste it from Grok)
        generated_code = simpledialog.askstring("Paste Generated Code", "Paste the code from Grok/ChatGPT here:")
        if not generated_code:
            return

        # Step 6: Preview and confirm
        preview_win = tk.Toplevel(self.root)
        preview_win.title("Code Preview – Check before writing")
        preview_text = scrolledtext.ScrolledText(preview_win, wrap=tk.WORD, font=("Consolas", 10))
        preview_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        preview_text.insert(tk.END, generated_code)
        preview_text.config(state="disabled")  # read-only

        if messagebox.askyesno("Confirm Write", 
                               f"Write this code to:\n{full_path}\n\n(Backup will be made if file already exists)"):
            preview_win.destroy()
            try:
                dir_path = os.path.dirname(full_path)
                os.makedirs(dir_path, exist_ok=True)

                # Backup if exists
                if os.path.exists(full_path):
                    backup_path = full_path + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    os.rename(full_path, backup_path)
                    self.log_text.insert(tk.END, f"\nBacked up existing file to: {backup_path}\n")

                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(generated_code)

                msg = f"Code successfully written to:\n{full_path}"
                self.log_text.insert(tk.END, "\n" + "="*70 + f"\n{msg}\n" + "="*70 + "\n")
                self.log_text.see(tk.END)
                messagebox.showinfo("Success", msg)
            except Exception as e:
                messagebox.showerror("Write Failed", f"Could not write file:\n{str(e)}")
                self.log_text.insert(tk.END, f"\nERROR writing {full_path}: {str(e)}\n")
        else:
            preview_win.destroy()
            messagebox.showinfo("Cancelled", "Write cancelled – no changes made.")

    # ── Reusable progress popup ─────────────────────────────────────────
    def show_progress_popup(self, title="Working...", steps=None):
        if not steps:
            return

        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.geometry("420x160")
        popup.transient(self.root)
        popup.grab_set()
        popup.resizable(False, False)

        tk.Label(popup, text=title, font=("Segoe UI", 12, "bold")).pack(pady=(10, 5))

        status_label = tk.Label(popup, text="Starting...", font=("Segoe UI", 10), wraplength=380)
        status_label.pack(pady=5)

        progress_bar = ttk.Progressbar(popup, length=360, mode='determinate')
        progress_bar.pack(pady=10)

        def update_progress(index, text):
            percent = (index / len(steps)) * 100 if steps else 0
            progress_bar["value"] = percent
            status_label.config(text=text)
            popup.update_idletasks()

        try:
            for i, (desc, func) in enumerate(steps, 1):
                update_progress(i-1, f"{desc} ({i}/{len(steps)})")
                func()
            update_progress(len(steps), "Finished!")
            popup.after(800, popup.destroy)
        except Exception as e:
            status_label.config(text=f"Error: {str(e)}", fg="red")
            progress_bar.stop()
            progress_bar["mode"] = 'indeterminate'
            tk.Button(popup, text="Close", command=popup.destroy).pack(pady=10)
            print("Progress popup error:", traceback.format_exc())

    # ── Your other methods (load_logs, check_toolchain, etc.) remain unchanged ──
    # Paste the rest of your class here (load_logs, clear_log_output, apply_log_filter, 
    # check_toolchain, run_tauri_dev, generate_plugin, open_task_planner, build_prompt, show_help)

    def load_logs(self):
        try:
            if not os.path.exists(LOG_FILE):
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    f.write("")

            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            self.log_text.insert(tk.END, content)
            self.log_text.see(tk.END)
        except Exception as e:
            msg = f"Cannot read log file:\n{str(e)}\n\nPath: {LOG_FILE}"
            self.log_text.insert(tk.END, "\n" + "="*70 + "\n" + msg + "\n" + "="*70 + "\n")
            print(msg)
            messagebox.showwarning("Log Read Issue", msg)

    # ... (add your other methods here: clear_log_output, apply_log_filter, etc.)

    def clear_log_output(self):
        self.log_text.delete("1.0", tk.END)

    def apply_log_filter(self):
        keyword = self.filter_keyword.get().strip().lower()
        if not keyword:
            self.load_logs()
            return

        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                lines = [line for line in f if keyword in line.lower()]
            self.log_text.delete("1.0", tk.END)
            self.log_text.insert(tk.END, "".join(lines))
            self.log_text.see(tk.END)
        except Exception as e:
            messagebox.showerror("Filter Error", str(e))

    def check_toolchain(self):
        def perform_checks():
            tools = {
                "cargo": "cargo --version",
                "rustc": "rustc --version",
                "node":  "node --version",
                "npm":   "npm --version",
                "git":   "git --version"
            }
            results = {}
            for tool, cmd in tools.items():
                try:
                    out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=8)
                    results[tool] = "✅ " + out.strip().splitlines()[0]
                except Exception as e:
                    results[tool] = f"❌ {str(e)[:50]}"

            message = "\n".join(f"{tool:6} : {status}" for tool, status in results.items())
            self.root.after(0, lambda: messagebox.showinfo("Toolchain Check", message or "No results?"))

        self.show_progress_popup("Checking Toolchain", [
            ("Running version checks...", perform_checks)
        ])

    def run_tauri_dev(self):
        def launch_tauri():
            try:
                cwd = os.path.join(PROJECT_PATH, "HexHawk")
                if not os.path.isdir(cwd):
                    raise FileNotFoundError(f"Tauri project folder not found:\n{cwd}")
                subprocess.Popen("npm run tauri dev", cwd=cwd, shell=True)
                return "Tauri dev mode started in new process."
            except Exception as e:
                raise RuntimeError(str(e))

        self.show_progress_popup("Launching Tauri Dev", [
            ("Starting dev server and backend...", launch_tauri)
        ])

    def generate_plugin(self):
        name = simpledialog.askstring("New Plugin", "Plugin name (no spaces recommended):")
        if not name or not name.strip():
            return

        name = name.strip().replace(" ", "_")
        folder = os.path.join(PLUGINS_DIR, name)
        path = os.path.join(folder, "lib.rs")

        def create_plugin():
            os.makedirs(folder, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(f'''// {name}/lib.rs
pub fn init() {{
    println!("Plugin '{name}' initialized.");
}}
''')

        self.show_progress_popup("Creating Plugin", [
            (f"Creating folder and lib.rs for '{name}'...", create_plugin),
            ("Done — plugin created!", lambda: None)
        ])

        messagebox.showinfo("Created", f"Plugin folder and lib.rs created:\n{path}")

    def open_task_planner(self):
        win = tk.Toplevel(self.root)
        win.title("Task Planner")
        win.geometry("540x480")

        listbox = tk.Listbox(win, font=("Segoe UI", 10), selectmode=tk.SINGLE)
        listbox.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        def save():
            tasks = list(listbox.get(0, tk.END))
            try:
                with open(TASKS_FILE, "w", encoding="utf-8") as f:
                    json.dump(tasks, f, indent=2)
                messagebox.showinfo("Saved", f"{len(tasks)} tasks saved.")
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

        def load():
            if not os.path.exists(TASKS_FILE):
                return
            try:
                with open(TASKS_FILE, "r", encoding="utf-8") as f:
                    tasks = json.load(f)
                listbox.delete(0, tk.END)
                for t in tasks:
                    listbox.insert(tk.END, t)
            except Exception as e:
                messagebox.showerror("Load failed", str(e))

        def add():
            task = simpledialog.askstring("New Task", "Enter task description:")
            if task and task.strip():
                listbox.insert(tk.END, task.strip())

        def delete():
            sel = listbox.curselection()
            if sel:
                listbox.delete(sel[0])

        btn_frame = tk.Frame(win)
        btn_frame.pack(fill=tk.X, padx=8, pady=6)

        tk.Button(btn_frame, text="Add",    command=add,    width=10).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Delete", command=delete, width=10).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Load",   command=load,   width=10).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn_frame, text="Save",   command=save,   width=10).pack(side=tk.RIGHT, padx=4)

        load()  # auto load

    def build_prompt(self):
        try:
            content = self.log_text.get("1.0", tk.END).strip()
            lines = [line for line in content.splitlines() if line.strip()][-12:]
            latest = "\n".join(lines)

            prompt = (
                "Context: Working on HexHawk – a Tauri + Rust + React reverse engineering tool.\n\n"
                "Recent log output:\n"
                "----------------------------------------\n"
                f"{latest}\n"
                "----------------------------------------\n\n"
                "What should I look at / fix next?"
            )

            pyperclip.copy(prompt)
            messagebox.showinfo("Copied to clipboard", "Last ~12 relevant log lines copied as prompt.")

            entry = {"timestamp": datetime.now().isoformat(), "prompt": prompt}
            history = []
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            history.append(entry)
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)

        except Exception as e:
            messagebox.showerror("Prompt Builder Error", str(e))

    def show_help(self):
        win = tk.Toplevel(self.root)
        win.title("HexHawk Help")
        win.geometry("820x580")

        notebook = ttk.Notebook(win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        for topic, content in HELP_CONTENT.items():
            frame = tk.Frame(notebook)
            text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Segoe UI", 10))
            text.pack(fill=tk.BOTH, expand=True)
            text.insert(tk.END, content)
            text.config(state="disabled")
            notebook.add(frame, text=topic)


if __name__ == "__main__":
    try:
        root = tk.Tk()
        root.withdraw()
        app = AssistantApp(root)
        root.deiconify()
        root.mainloop()
    except Exception as e:
        error_text = traceback.format_exc()
        print("STARTUP CRASH:\n" + "="*70 + "\n" + error_text + "\n" + "="*70, file=sys.stderr)

        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "HexHawk Assistant – Startup Failed",
                f"The application could not start properly.\n\n"
                f"Error: {str(e)}\n\n"
                f"Full traceback saved to console.\n\n"
                f"Common causes:\n"
                f"• Permission denied on log file\n"
                f"• Invalid characters / encoding in log file\n"
                f"• Project folder not accessible"
            )
            root.destroy()
        except:
            pass