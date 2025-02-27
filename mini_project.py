import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import hashlib
import threading
import logging
import yara
import concurrent.futures
import shutil
import stat
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification


class AntivirusScanner:
    def __init__(self, root):
        self.known_hashes = {}  # Known malware hashes (loaded/updated dynamically)
        self.infected_files = []
        self.quarantine_directory = "quarantine"
        self.scan_active = False
        self.yara_rules = None
        self.monitoring_active = True  # Track monitoring state
        self.observer = None  # Initialize observer variable
    
        icon_path = os.path.join(os.getcwd(), "antivirus.ico")  # Gets the current directory


        self.setup_quarantine_directory()

        logging.basicConfig(filename="scan_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

        # Tkinter GUI setup
        self.root = root
        self.root.title("Virus Scanner")
        self.root.geometry("1200x650")
        self.root.configure(bg="#2c3e50")  
        self.scan_mode = tk.StringVar(value="file")  # Default to File Scan
        self.setup_gui()

        # Load signatures after setting up the GUI
        self.load_signatures()  # Load signatures initially

        self.start_real_time_scan()

    def notify_user(self,message):
     try:
        # Cross-platform notification using plyer
        notification.notify(
            title="Antivirus Alert",
            message=message,
            app_icon="antivirus.ico",
            timeout=10
        )
     except Exception as e:
        logging.error(f"Error showing plyer notification: {e}")

    def setup_quarantine_directory(self):
        if not os.path.exists(self.quarantine_directory):
            try:
                os.makedirs(self.quarantine_directory)
            except PermissionError:
                self.result_text.insert(tk.END, "Error: No permission to create quarantine directory.\n")
                logging.error("No permission to create quarantine directory.")
                return False
        return True

    def load_signatures(self):
        try:
            # Attempt to load hash signatures
            hash_file_path = "malware_hashes.txt"
            yara_file_path = "rules.yar"

            if not os.path.exists(hash_file_path):
                self.result_text.insert(tk.END, f"Hash file not found: {hash_file_path}\n")
                return

            if not os.path.exists(yara_file_path):
                self.result_text.insert(tk.END, f"YARA rules file not found: {yara_file_path}\n")
                return

            self.known_hashes = self.load_hashes_from_file(hash_file_path)
            self.yara_rules = yara.compile(filepath=yara_file_path)
            self.result_text.insert(tk.END, "Signatures successfully loaded.\n")
        
        except yara.SyntaxError as e:
            self.result_text.insert(tk.END, f"Failed to load YARA rules: Syntax error in rules file.\n{e}\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Unexpected error loading signatures: {e}\n")


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

    def quarantine_file(self, file_path):
        if not self.setup_quarantine_directory():
            return

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

    def setup_gui(self):
        frame = tk.Frame(self.root, bg="#34495e")
        frame.pack(pady=20)

        # Add Quick Scan and Deep Scan options
        quick_scan_radiobutton = tk.Radiobutton(frame, text="Quick Scan", variable=self.scan_mode, value="quick", bg="#34495e", fg="white", selectcolor="#2c3e50")
        deep_scan_radiobutton = tk.Radiobutton(frame, text="Deep Scan", variable=self.scan_mode, value="deep", bg="#34495e", fg="white", selectcolor="#2c3e50")
        file_scan = tk.Radiobutton(frame, text="File Scan", variable=self.scan_mode, value="file", bg="#34495e", fg="white", selectcolor="#2c3e50")
        quick_scan_radiobutton.grid(row=0, column=3, padx=20)
        deep_scan_radiobutton.grid(row=0, column=2, padx=20)
        file_scan.grid(row=0, column=1, padx=20)

        scan_button = tk.Button(frame, text="Select & Scan", command=self.start_scan_thread, bg="#27ae60", fg="white", relief="flat")
        scan_button.grid(row=0, column=4, padx=20)

        stop_button = tk.Button(frame, text="Stop Scan", command=self.stop_scan, bg="#e74c3c", fg="white", relief="flat")
        stop_button.grid(row=0, column=5, padx=20)

        save_button = tk.Button(frame, text="Save Report", command=self.save_report, bg="#3498db", fg="white", relief="flat")
        save_button.grid(row=0, column=6, padx=20)

        update_button = tk.Button(frame, text="Update Signatures", command=self.update_signatures, bg="#f39c12", fg="black", relief="flat")
        update_button.grid(row=0, column=7, padx=20)

        self.stop_button = tk.Button(
            frame,
            text="Stop Monitoring",
            command=self.toggle_real_time_monitoring,
            bg="#e74c3c",
            fg="white",
            relief="flat"
        )
        self.stop_button.grid(row=0, column=8, padx=20, pady=20)

        quit_button = tk.Button(frame, text="Quit", command=self.quit_app, bg="#2c3e50", fg="white", relief="flat")
        quit_button.grid(row=0, column=9, padx=20)

        self.result_text = tk.Text(self.root, height=20, width=120, bg="#34495e", fg="white", insertbackground="white")
        self.result_text.pack(pady=20)

        scrollbar = tk.Scrollbar(self.root, command=self.result_text.yview)
        self.result_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100, style="modern.Horizontal.TProgressbar")
        self.progress_bar.pack(fill=tk.X, padx=20, pady=10)

    def save_report(self):
        with open('scan_report.txt', 'w') as report_file:
            report_file.write(self.result_text.get(1.0, tk.END))
        messagebox.showinfo("Information", "Report saved successfully.")
        self.result_text.insert(tk.END, "Report saved successfully.\n")

    def stop_scan(self):
     if not self.scan_active:
        messagebox.showinfo("Information", "No active scan is running.")
        return

     confirm = messagebox.askyesno("Stop Scan", "Are you sure you want to stop the scan?")
     if confirm:
        self.scan_active = False  
        self.result_text.insert(tk.END, "Stopping scan... Please wait.\n")



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
     if self.scan_active:
        messagebox.showwarning("Scan Running", "A scan is already in progress. Please wait for it to complete.")
        return  # Prevent starting a new scan

     self.scan_active = True  # Set scan to active only if no scan is running
     threading.Thread(target=self.select).start()
     self.scan_active = False



    def select(self):
     self.clear_results()
     self.infected_files.clear()

     mode = self.scan_mode.get()
     if mode == "file":
        path = filedialog.askopenfilename()
        if path:
            self.scan_file(path, deep_scan=True)
     elif mode == "quick":
        # Scan common infection-prone directories instead of entire user directory
        quick_scan_paths = [
            os.path.join(os.path.expanduser("~"), "Downloads")
        ]
        for directory in quick_scan_paths:
            if os.path.exists(directory):
                self.scan_directory_concurrent(directory, deep_scan=False)
     elif mode == "deep":
        path = filedialog.askdirectory()
        if path:
            self.scan_directory_concurrent(path, deep_scan=True)

     if self.infected_files:
        self.show_infected_files_window()



    def compute_file_hash(self, file_path, hash_type="md5"):
        if hash_type not in {"md5", "sha256"}:
            self.result_text.insert(tk.END, f"Unsupported hash type: {hash_type}\n")
            return None
        hash_func = hashlib.md5() if hash_type == "md5" else hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except (PermissionError) as e:
         self.result_text.insert(tk.END, f"Permission denied for : {file_path}\n")
         logging.error (f"Permissino denied for {file_path}: {e}")
        except (OSError) as e:
         self.result_text.insert(tk.END, f"Cant't read file : {file_path}\n")
         logging.error(f"Error reading file {file_path}: {e}")
         return None



    def scan_file(self, file_path, deep_scan):
     if not os.path.isfile(file_path):
        return  # Suppress message for invalid file

     try:
        virus_found = False
        severity_score = 0

        # Debug: Print known hashes before comparison
        #print("Complete Known Hashes Dictionary:", self.known_hashes)

        # Compute file hashes
        try:
            file_md5 = self.compute_file_hash(file_path, "md5").lower().strip()
            file_sha256 = self.compute_file_hash(file_path, "sha256").lower().strip()
            #print(f"Computed MD5: {file_md5}, Computed SHA256: {file_sha256}")  # Debugging
        except Exception as e:
            logging.error(f"Error computing hash for {file_path}: {e}")
            return False

        # Extract known hashes correctly
        known_md5_hashes = {h.replace('"', '').replace(',', '').strip().lower() for k, h in self.known_hashes.items() if "_MD5" in k.upper()}
        known_sha256_hashes = {h.replace('"', '').replace(',', '').strip().lower() for k, h in self.known_hashes.items() if "_SHA256" in k.upper()}

        
        '''print("Known MD5 Hashes:", known_md5_hashes)  # Debugging
        print("Known SHA256 Hashes:", known_sha256_hashes)  # Debugging'''

        # Check if file matches known malware hashes
        if file_md5 in known_md5_hashes or file_sha256 in known_sha256_hashes:
            self.result_text.insert(tk.END, f"⚠️ Known virus found in {file_path} (Hash match: {file_md5 if file_md5 in known_md5_hashes else file_sha256})\n")
            virus_found = True
            severity_score += 50      

        # Apply YARA rules (Deep Scan)
        if self.yara_rules and deep_scan:
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                    matches = self.yara_rules.match(data=file_data)
                    if matches:
                        self.result_text.insert(tk.END, f"⚠️ YARA match found in {file_path}: {matches}\n")
                        virus_found = True
                        severity_score += 75  # Increase severity if YARA rule matches
            except yara.Error as e:
                logging.error(f"Error processing YARA rules for {file_path}: {e}")
            except Exception as e:
                logging.error(f"Error reading file {file_path} for YARA scan: {e}")

        # If a virus was found, display heuristic analysis and log
        if virus_found:
            self.display_heuristic_analysis(file_path, severity_score)
            self.infected_files.append(file_path)
            logging.info(f"Infected file detected: {file_path}, Severity: {severity_score}")
            return True
        else:
            self.result_text.insert(tk.END, f"✅ No issues detected in {file_path}\n")

        return False

     except PermissionError as e:
        logging.error(f"Permission denied for file: {file_path} - {e}")
        return False
     except FileNotFoundError:
        logging.warning(f"File not found during scan: {file_path}")
        return False
     except OSError:
        logging.warning(f"Error accessing file during scan: {file_path}")
        return False



    def scan_directory_concurrent(self, directory, deep_scan):
     if self.scan_active:  # Prevent multiple scans from running at the same time
        messagebox.showwarning("Scan Running", "A scan is already in progress. Please wait for it to complete.")
        return

     self.scan_active = True  
     start_time = time.time()
     files = [os.path.join(root, file) for root, _, filenames in os.walk(directory) for file in filenames]
     total_files = len(files)

     if total_files == 0:
        self.result_text.insert(tk.END, "No files found in the directory to scan.\n")
        self.scan_active = False  
        return

     scanned_files = 0
     threats_found = 0

     with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(self.scan_file, file, deep_scan): file for file in files}

        for future in concurrent.futures.as_completed(futures):
            if not self.scan_active:  
                self.result_text.insert(tk.END, "Scan manually stopped by user.\n")
                self.scan_active = False  # Reset flag to allow future scans
                return  

            scanned_files += 1
            if future.result():
                threats_found += 1
            if scanned_files % 100 == 0:
                self.progress_var.set(scanned_files / total_files * 100)
                self.progress_bar.update()

     self.scan_active = False  
     elapsed_time = time.time() - start_time
     self.result_text.insert(tk.END, f"\nScan Complete\nFiles Scanned: {scanned_files}\nThreats Found: {threats_found}\nTime Taken: {elapsed_time:.2f} seconds\n")



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
        selection_window.configure(bg="#34495e")

        list_frame = tk.Frame(selection_window, bg="#34495e")
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)

        tk.Label(selection_window, text="Select files to quarantine or delete:", font=("Arial", 12, "bold"), bg="#34495e", fg="white").pack(pady=10)

        canvas = tk.Canvas(list_frame, bg="#34495e")
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#34495e")

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
            chk = tk.Checkbutton(scrollable_frame, text=file_path, variable=var, anchor="w", justify="left", wraplength=450, bg="#34495e", fg="white", selectcolor="#2c3e50")
            chk.pack(fill="x", padx=10, pady=5)

        button_frame = tk.Frame(selection_window, bg="#34495e")
        button_frame.pack(fill="x", padx=10, pady=10)

        select_all_button = tk.Button(button_frame, text="Select All", command=lambda: self.select_all(file_vars), bg="#3498db", fg="white", relief="flat")
        select_all_button.pack(side="left", padx=5)

        deselect_all_button = tk.Button(button_frame, text="Deselect All", command=lambda: self.deselect_all(file_vars), bg="#e67e22", fg="white", relief="flat")
        deselect_all_button.pack

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
        messagebox.showinfo("file(s) Quarantined successfully.")
        

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

    def toggle_real_time_monitoring(self):
        """Toggle real-time monitoring on or off."""
        if self.monitoring_active:
            # Stop real-time monitoring
            self.stop_real_time_scan()
            self.stop_button.config(text="Start Monitoring", bg="green", fg="white")
        else:
            # Start real-time monitoring
            self.start_real_time_scan()
            self.stop_button.config(text="Stop Monitoring", bg="red", fg="white")
        self.monitoring_active = not self.monitoring_active

    def start_real_time_scan(self):
     self.clear_results()
     if hasattr(self, 'observer') and self.observer and self.observer.is_alive():
        self.result_text.insert(tk.END, "Real-time scanning is already running.\n")
        return

     directories = ["D:/"]  # Directories to monitor
     self.excluded_directories = ["C:/Windows", "D:/mini","C:/Users","C:/ProgramData"]  # Excluded directories

     self.result_text.insert(tk.END, f"Started real-time scanning for changes in {', '.join(directories)}.\n")
    
     notification.notify(
    title="Antivirus Scan",
    message="Real-time system scanning has started.",
    app_icon="antivirus.ico",
    timeout=10  # Duration in seconds
)

     self.observer = Observer()
     event_handler = FileChangeHandler(self, self.excluded_directories)

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
            # Update YARA rules
            self.yara_rules = yara.compile(filepath=yara_file_path)
            self.result_text.insert(tk.END, "YARA rules updated successfully.\n")
        except yara.SyntaxError as e:
            self.result_text.insert(tk.END, f"Error updating YARA rules: {e}\n")
            logging.error(f"Error updating YARA rules: {e}")
        except Exception as e:
            self.result_text.insert(tk.END, f"Unexpected error updating YARA rules: {e}\n")
            logging.error(f"Unexpected error updating YARA rules: {e}")

        try:
            # Update known malware hashes
            self.known_hashes = self.load_hashes_from_file(hashes_file_path)
            self.result_text.insert(tk.END, "Malware hashes updated successfully.\n")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error updating malware hashes: {e}\n")
            logging.error(f"Error updating malware hashes: {e}")



class FileChangeHandler(FileSystemEventHandler):
    """Handler for real-time file change events with directory exclusion."""

    def __init__(self, antivirus, excluded_dirs):
        self.antivirus = antivirus
        self.excluded_dirs = set(os.path.abspath(dir_path) for dir_path in excluded_dirs)  # Normalize paths

    def should_exclude(self, file_path):
        """Check if the file is inside an excluded directory."""
        file_path = os.path.abspath(file_path)  # Get absolute path
        return any(file_path.startswith(excluded) for excluded in self.excluded_dirs)

    def on_created(self, event):
     if not event.is_directory and not self.should_exclude(event.src_path):
        if self.antivirus.scan_file(event.src_path, deep_scan=True):
            self.antivirus.notify_user(f"Malware detected in newly created file: {event.src_path}")
            self.antivirus.quarantine_file(event.src_path)
            self.antivirus.notify_user(f"File quarantined: {event.src_path}")
        else:
            logging.warning(f"File was deleted before scan: {event.src_path}")

    def on_modified(self, event):
     if not event.is_directory and not self.should_exclude(event.src_path):
        if os.path.exists(event.src_path) and self.antivirus.scan_file(event.src_path, deep_scan=True):
            self.antivirus.notify_user(f"Malware detected in modified file: {event.src_path}")
            self.antivirus.quarantine_file(event.src_path)
            self.antivirus.notify_user(f"File quarantined: {event.src_path}")
        else:
            logging.warning(f"File was deleted before scan: {event.src_path}")

                
root = tk.Tk()
app = AntivirusScanner(root)
root.mainloop()
