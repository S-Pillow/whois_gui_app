import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import whois
import csv
import concurrent.futures
import socket
import re


class WhoisLookupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("WHOIS Lookup Tool")
        self.domains = []
        self.results = []

        # Text area for domain input
        self.text_area = tk.Text(root, height=10, width=50)
        self.text_area.pack(pady=10)

        # Button to load domains from file
        self.file_button = tk.Button(root, text="Load Domains from File", command=self.load_domains)
        self.file_button.pack(pady=5)

        # Button to start lookup
        self.lookup_button = tk.Button(root, text="Start WHOIS Lookup", command=self.start_lookup)
        self.lookup_button.pack(pady=5)

        # Progress bar
        self.progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=5)

        # Text area for results
        self.results_area = tk.Text(root, height=10, width=50, state=tk.DISABLED)
        self.results_area.pack(pady=10)

        # Button to clear input and results
        self.clear_button = tk.Button(root, text="Clear Input and Results", command=self.clear_text)
        self.clear_button.pack(pady=5)

        # Button to save results to CSV
        self.save_button = tk.Button(root, text="Save Results to CSV", command=self.save_results, state=tk.DISABLED)
        self.save_button.pack(pady=5)

    def clear_text(self):
        """Clear the input and results text boxes"""
        self.text_area.delete(1.0, tk.END)
        self.results_area.config(state=tk.NORMAL)
        self.results_area.delete(1.0, tk.END)
        self.results_area.config(state=tk.DISABLED)

    def load_domains(self):
        """Load domain names from a text file"""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "r") as f:
                self.domains = [line.strip() for line in f.readlines() if line.strip()]
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, "\n".join(self.domains))

    def start_lookup(self):
        """Trigger the WHOIS lookup process"""
        self.domains = self.text_area.get(1.0, tk.END).splitlines()
        self.domains = [domain.strip() for domain in self.domains if domain.strip()]

        if not self.domains:
            messagebox.showerror("Error", "Please enter or load domain names.")
            return

        self.results = []
        self.progress['value'] = 0
        self.progress['maximum'] = len(self.domains)

        self.save_button.config(state=tk.DISABLED)
        self.lookup_button.config(state=tk.DISABLED)

        # Perform lookups in the background using multi-threading
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.perform_whois_lookup, domain): domain for domain in self.domains}

            for future in concurrent.futures.as_completed(futures):
                domain, registrar = future.result()
                self.results.append((domain, registrar))
                
                # Update the UI in the main thread using root.after
                self.root.after(0, self.update_results, domain, registrar)
                self.root.after(0, self.progress.step, 1)

        self.save_button.config(state=tk.NORMAL)
        self.lookup_button.config(state=tk.NORMAL)

    def perform_whois_lookup(self, domain, timeout=10):
        """Perform WHOIS lookup for a single domain with a timeout"""
        try:
            socket.setdefaulttimeout(timeout)
            w = whois.whois(domain)

            # Try to get the registrar from the response
            registrar = w.registrar

            # Fallback to raw WHOIS text if the registrar is not found
            if not registrar:
                raw_text = w.text
                registrar = self.extract_registrar_from_raw_whois(raw_text)

            return domain, registrar or "Registrar not found"
        except whois.parser.PywhoisError:
            return domain, "Invalid domain"
        except socket.timeout:
            return domain, "Timeout during WHOIS lookup"
        except Exception as e:
            return domain, f"Error: {str(e)}"

    def extract_registrar_from_raw_whois(self, raw_text):
        """Extract the registrar from raw WHOIS data using extended regular expressions"""
        try:
            # Extended regex pattern to match 'Registrar:', 'Sponsoring Registrar:', or 'Domain Registrar:'
            match = re.search(r"(Registrar|Sponsoring Registrar|Domain Registrar):\s*(.+)", raw_text, re.IGNORECASE)
            if match:
                return match.group(2).strip()
            else:
                return None
        except Exception as e:
            return "Error extracting registrar"

    def update_results(self, domain, registrar):
        """Update the results area with new lookup info"""
        self.results_area.config(state=tk.NORMAL)
        self.results_area.insert(tk.END, f"{domain}: {registrar}\n")
        self.results_area.config(state=tk.DISABLED)

    def save_results(self):
        """Save the lookup results to a CSV file"""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if file_path:
            with open(file_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Domain", "Registrar"])
                writer.writerows(self.results)
            messagebox.showinfo("Success", f"Results saved to {file_path}")


# Main loop for the Tkinter app
if __name__ == "__main__":
    root = tk.Tk()
    app = WhoisLookupApp(root)
    root.mainloop()
