import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import hashlib
import re
import threading
import logging
import yara
import concurrent.futures
import shutil
import stat
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification



class AntivirusScanner:
    def __init__(self, root):
        self.known_hashes = {}  # Known malware hashes (loaded/updated dynamically)
        self.suspicious_patterns = [
            b"shell32.dll", b"kernel32.dll", b"CreateProcess", b"cmd.exe", b"subprocess", b"socket",
            b"bind", b"connect", b"exec", b"CreateFileA", b"RegOpenKeyEx", b"VirtualAlloc", b"WinExec"
        ]
        self.infected_files = []
        self.quarantine_directory = "quarantine"
        self.scan_active = False
        self.yara_rules = None

        self.setup_quarantine_directory()
        

        logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

        # Tkinter GUI setup
        self.root = root
        self.root.title("Antivirus Scanner")
        self.root.geometry("1000x650")
        self.scan_mode = tk.StringVar(value="file")
        self.setup_gui()

        # Load signatures after setting up the GUI
        self.load_signatures()  # Load signatures initially
        self.start_real_time_scan()

    def notify_user(self, message):
    
     notification.notify(
        title="Antivirus Alert",
        message=message,
        timeout=10  # Duration the notification will appear
     )
     logging.info(f"Notification: {message}")


    def setup_quarantine_directory(self):
        if not os.path.exists(self.quarantine_directory):
            os.makedirs(self.quarantine_directory)

    # Function to load signatures (both hash signatures and YARA rules)
    def load_signatures(self):
        try:
            # Attempt to load hash signatures
            self.known_hashes = self.load_hashes_from_file("D:/malware_hashes.txt")
            # Load YARA rules
            self.yara_rules = yara.compile(filepath="D:/rules.yar")
            self.result_text.insert(tk.END, "Signatures successfully loaded.\n")
        except FileNotFoundError:
            self.result_text.insert(tk.END, "Failed to load signatures: File not found.\n")
        except yara.YaraSyntaxError as e:
            self.result_text.insert(tk.END, f"Failed to load YARA rules: Syntax error in rules file.\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Failed to load signatures: {e}\n")

    # Load hash signatures from a file
    def load_hashes_from_file(self, file_path):
        hashes = {}
        try:
            with open(file_path, "r") as file:
                for line in file:
                    if ':' not in line:
                        logging.warning(f"Skipped malformed line in hash file: {line.strip()}")
                        continue
                    hash_type, hash_value = line.strip().split(":", 1)
                    hashes[hash_type] = hash_value
            return hashes
        except FileNotFoundError:
            self.result_text.insert(tk.END, f"Error: {file_path} not found.\n")
            logging.error(f"File not found: {file_path}")
            return {}
        except Exception as e:
            self.result_text.insert(tk.END, f"Error loading hash file: {e}\n")
            logging.error(f"Error loading hash file {file_path}: {e}")
            return {}

    # Function to move infected files to quarantine
    def quarantine_file(self, file_path):
        try:
            filename = os.path.basename(file_path)
            quarantined_path = os.path.join(self.quarantine_directory, filename)
            shutil.move(file_path, quarantined_path)
            os.chmod(quarantined_path, stat.S_IRUSR | stat.S_IWUSR)
            logging.info(f"File {file_path} quarantined to {quarantined_path}")
            self.result_text.insert(tk.END, f"File {file_path} moved to quarantine and made non-executable.\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error quarantining file {file_path}: {e}\n")
            logging.error(f"Error quarantining file {file_path}: {e}")

    # Setup the GUI
    def setup_gui(self):
        frame = tk.Frame(self.root)
        frame.pack(pady=20)

        file_radiobutton = tk.Radiobutton(frame, text="Scan File", variable=self.scan_mode, value="file")
        directory_radiobutton = tk.Radiobutton(frame, text="Scan Directory", variable=self.scan_mode, value="directory")
        file_radiobutton.grid(row=0, column=0, padx=20)
        directory_radiobutton.grid(row=0, column=1, padx=20)

        scan_button = tk.Button(frame, text="Select & Scan", command=self.start_scan_thread, bg="green", fg="white")
        scan_button.grid(row=0, column=2, padx=20)

        stop_button = tk.Button(frame, text="Stop Scan", command=self.stop_scan, bg="red", fg="white")
        stop_button.grid(row=0, column=3, padx=20)

        save_button = tk.Button(frame, text="Save Report", command=self.save_report, bg="blue", fg="white")
        save_button.grid(row=0, column=4, padx=20)

        update_button = tk.Button(frame, text="Update Signatures", command=self.update_signatures, bg="orange", fg="black")
        update_button.grid(row=0, column=5, padx=20)

        

        

        stop_button = tk.Button(frame, text="Stop Real-Time Scan", command=self.stop_real_time_scan, bg="red", fg="white")
        stop_button.grid(row=0, column=6, padx=20,pady=20)

        quit_button = tk.Button(frame, text="Quit", command=self.quit_app, bg="black", fg="white")
        quit_button.grid(row=0, column=8, padx=20)

        self.result_text = tk.Text(self.root, height=20, width=120)
        self.result_text.pack(pady=20)

        scrollbar = tk.Scrollbar(self.root, command=self.result_text.yview)
        self.result_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20, pady=10)

    # Save the scan results to a file
    def save_report(self):
        with open('scan_report.txt', 'w') as report_file:
            report_file.write(self.result_text.get(1.0, tk.END))
        self.result_text.insert(tk.END, "Report saved successfully.\n")
    
    def stop_scan(self):
        self.scan_active = False
        self.result_text.insert(tk.END, "Scan stopped.\n")

    # Quit the application
    def quit_app(self):
     confirm = messagebox.askyesno("Exit Application", "Are you sure you want to exit the application?")
     if confirm:
        if hasattr(self, 'observer') and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        self.result_text.insert(tk.END, "Exiting the application.\n")
        self.root.quit()


    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.progress_var.set(0)

    def start_scan_thread(self):
        self.scan_active = True
        threading.Thread(target=self.select).start()

    def select(self):
        self.clear_results()
        self.infected_files.clear()
        if self.scan_mode.get() == "file":
            file_path = filedialog.askopenfilename()
            if file_path:
                self.scan_file(file_path)
            else:
                self.result_text.insert(tk.END, "No file selected.\n")
        else:
            directory_path = filedialog.askdirectory()
            if directory_path:
                self.scan_directory_concurrent(directory_path)
            else:
                self.result_text.insert(tk.END, "No directory selected.\n")
        if self.infected_files:
            self.show_infected_files_window()

    def compute_file_hash(self, file_path, hash_type="md5"):
        hash_func = hashlib.md5() if hash_type == "md5" else hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except OSError as e:
            self.result_text.insert(tk.END, f"Error reading file: {e}\n")
            return None
    def scan_file(self, file_path):
     if not os.path.isfile(file_path):
        self.result_text.insert(tk.END, f"{file_path} is not a valid file.\n")
        return
     try:
        virus_found = False
        heuristic_alert = False
        severity_score = 0

        # Compute file hash
        file_md5 = self.compute_file_hash(file_path, "md5")
        file_sha256 = self.compute_file_hash(file_path, "sha256")

        if file_md5 in self.known_hashes.values():
            self.result_text.insert(tk.END, f"Known virus found (MD5 match) in {file_path}\n")
            virus_found = True
            severity_score += 50
        elif file_sha256 in self.known_hashes.values():
            self.result_text.insert(tk.END, f"Known virus found (SHA-256 match) in {file_path}\n")
            virus_found = True
            severity_score += 75

        if self.yara_rules:
            try:
                matches = self.yara_rules.match(file_path)
                if matches:
                    self.result_text.insert(tk.END, f"YARA match found in {file_path}: {matches}\n")
                    virus_found = True
                    severity_score += 75
            except yara.Error as e:
                self.result_text.insert(tk.END, f"Error processing YARA rules for {file_path}: {e}\n")
                logging.error(f"Error processing YARA rules for {file_path}: {e}")
                return  # Skip this file if YARA cannot process it

        with open(file_path, "rb") as f:
            content = f.read()
            for pattern in self.suspicious_patterns:
                if re.search(pattern, content):
                    self.result_text.insert(tk.END, f"Suspicious pattern {pattern} found in {file_path}\n")
                    heuristic_alert = True
                    severity_score += 50

        if virus_found or heuristic_alert:
            self.display_heuristic_analysis(file_path, severity_score)
            self.infected_files.append(file_path)
            logging.info(f"Infected file: {file_path}, Severity: {severity_score}")
        else:
            self.result_text.insert(tk.END, f"No issues detected in {file_path}\n")
            logging.info(f"File scanned: {file_path} - No issues found.")
            
     except OSError as e:
        self.result_text.insert(tk.END, f"Error scanning file: {e}\n")
        logging.error(f"Error scanning file {file_path}: {e}")
    
    


    



    


    def scan_directory_concurrent(self, directory_path):
        files = [os.path.join(root, file) for root, _, filenames in os.walk(directory_path) for file in filenames]
        total_files = len(files)
        if total_files == 0:
            self.result_text.insert(tk.END, "No files found in the selected directory.\n")
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.scan_file, file): file for file in files}
            for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                if not self.scan_active:
                    self.result_text.insert(tk.END, "Scan stopped by user.\n")
                    return
                self.update_progress(idx, total_files)
        self.progress_var.set(0)
        self.progress_bar.update()

    def display_heuristic_analysis(self, file_path, severity_score):
        severity_percentage = min(severity_score, 100)
        if severity_percentage >= 75:
            severity_level = "High Risk"
            color = "red"
        elif 50 <= severity_percentage < 75:
            severity_level = "Moderate Risk"
            color = "orange"
        else:
            severity_level = "Low Risk"
            color = "green"
        
        self.result_text.insert(tk.END, f"Heuristic Analysis for {file_path}: {severity_level} ({severity_percentage}% severity)\n")
        self.result_text.tag_add(severity_level, f"{float(self.result_text.index('end')) - 2} linestart", "end")
        self.result_text.tag_config(severity_level, foreground=color)

    def update_progress(self, current, total):
        self.progress_var.set(current / total * 100)
        self.progress_bar.update()

    def show_infected_files_window(self):
        if not self.infected_files:
            messagebox.showinfo("No Infected Files", "No infected files were found.")
            return

        selection_window = tk.Toplevel(self.root)
        selection_window.title("Infected Files Detected")
        selection_window.geometry("500x400")

        list_frame = tk.Frame(selection_window)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Label(selection_window, text="Select files to quarantine or delete:", font=("Arial", 12, "bold")).pack(pady=10)

        canvas = tk.Canvas(list_frame)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        file_vars = {}

        for file_path in self.infected_files:
            var = tk.IntVar()
            file_vars[file_path] = var
            chk = tk.Checkbutton(scrollable_frame, text=file_path, variable=var, anchor="w", justify="left", wraplength=450)
            chk.pack(fill="x", padx=10, pady=5)

        button_frame = tk.Frame(selection_window)
        button_frame.pack(fill="x", padx=10, pady=10)

        select_all_button = tk.Button(button_frame, text="Select All", command=lambda: self.select_all(file_vars), bg="#3498db", fg="white")
        select_all_button.pack(side="left", padx=5)

        deselect_all_button = tk.Button(button_frame, text="Deselect All", command=lambda: self.deselect_all(file_vars), bg="#e67e22", fg="white")
        deselect_all_button.pack(side="left", padx=5)

        quarantine_button = tk.Button(button_frame, text="Quarantine Selected Files", command=lambda: self.quarantine_selected_files(file_vars), bg="yellow", fg="black")
        quarantine_button.pack(side="left", padx=5)

        delete_button = tk.Button(button_frame, text="Delete Selected Files", command=lambda: self.delete_selected_files(file_vars), bg="red", fg="white")
        delete_button.pack(side="left", padx=5)

        cancel_button = tk.Button(button_frame, text="Cancel", command=selection_window.destroy, bg="gray", fg="white")
        cancel_button.pack(side="left", padx=5)

    def quarantine_selected_files(self, file_vars):
        self.setup_quarantine_directory()
        for file_path, var in file_vars.items():
            if var.get() == 1:
                self.quarantine_file(file_path)

    def delete_selected_files(self, file_vars):
        deleted_files = []
        for file_path, var in file_vars.items():
            if var.get() == 1:
                try:
                    os.remove(file_path)
                    self.result_text.insert(tk.END, f"File {file_path} deleted successfully.\n")
                    deleted_files.append(file_path)
                    logging.info(f"File {file_path} deleted successfully.")
                except OSError as e:
                    self.result_text.insert(tk.END, f"Error deleting file {file_path}: {e}\n")
                    logging.error(f"Error deleting file {file_path}: {e}")
        
        for file in deleted_files:
            self.infected_files.remove(file)
        
        if deleted_files:
            messagebox.showinfo("Files Deleted", f"{len(deleted_files)} file(s) deleted successfully.")

    def select_all(self, file_vars):
        for var in file_vars.values():
            var.set(1)

    def deselect_all(self, file_vars):
        for var in file_vars.values():
            var.set(0)

    def start_real_time_scan(self):
        self.clear_results()
        if hasattr(self, 'observer') and self.observer and self.observer.is_alive():
            self.result_text.insert(tk.END, "Real-time scanning is already running.\n")
            return

        directories = ["D:/", "E:/"]
        self.result_text.insert(tk.END, f"Started real-time scanning for changes in {', '.join(directories)}.\n")
        notification.notify(
            title="Antivirus Scan",
            message="Real-time system scanning has started.",
            timeout=10
        )
        self.observer = Observer()
        event_handler = FileChangeHandler(self)

        for directory in directories:
            if os.path.exists(directory):
                self.observer.schedule(event_handler, directory, recursive=True)
            else:
                self.result_text.insert(tk.END, f"Directory does not exist: {directory}\n")

        self.observer.start()

    def stop_real_time_scan(self):
        if hasattr(self, 'observer') and self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.result_text.insert(tk.END, "Real-time scanning stopped.\n")
        else:
            self.result_text.insert(tk.END, "No active real-time scanning to stop.\n")


    def update_signatures(self):
        yara_file_path = filedialog.askopenfilename(title="Select YARA Rules File", filetypes=[("YARA files", "*.yar")])
        if not yara_file_path:
            self.result_text.insert(tk.END, "YARA rules file not selected.\n")
            return

        hashes_file_path = filedialog.askopenfilename(title="Select Malware Hashes File", filetypes=[("Text files", "*.txt")])
        if not hashes_file_path:
            self.result_text.insert(tk.END, "Malware hashes file not selected.\n")
            return

        try:
            self.yara_rules = yara.compile(filepath=yara_file_path)
            self.known_hashes = self.load_hashes_from_file(hashes_file_path)
            self.result_text.insert(tk.END, "Signatures updated from local files.\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Failed to load signatures from local files: {e}\n")


class FileChangeHandler(FileSystemEventHandler):
    """Handler for real-time file change events."""

    def __init__(self, antivirus):
        self.antivirus = antivirus

    def on_created(self, event):
        if not event.is_directory:
            self.antivirus.result_text.insert(tk.END, f"File created: {event.src_path}. Scanning...\n")
            self.antivirus.scan_file(event.src_path)
            self.antivirus.notify_user(f"Malware detected at {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self.antivirus.result_text.insert(tk.END, f"File modified: {event.src_path}. Scanning...\n")
            self.antivirus.scan_file(event.src_path)
            self.antivirus.notify_user(f"Malware detected at {event.src_path}")


# Run the application
root = tk.Tk()
app = AntivirusScanner(root)
root.mainloop()
