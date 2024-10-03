import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QProgressBar, QFileDialog, QTableWidget, QTableWidgetItem, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
import whois
import csv
import socket
import time
import math


class WhoisLookupThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, str, str)

    def __init__(self, domains):
        super().__init__()
        self.domains = domains

    def run(self):
        for i, domain in enumerate(self.domains):
            domain, registrar, registrant_name = self.perform_whois_lookup(domain)
            self.result_signal.emit(domain, registrar, registrant_name)
            self.progress_signal.emit(1)  # Emit progress increment by 1

    def perform_whois_lookup(self, domain, timeout=10, retries=5, delay_between_requests=1):
        """Perform WHOIS lookup for a single domain with retry logic and delay"""
        for attempt in range(retries):
            try:
                socket.setdefaulttimeout(timeout)
                w = whois.whois(domain)

                # Get the registrar and registrant name from the response
                registrar = w.registrar if w.registrar else "Registrar not found"
                registrant_name = w.get('registrant_name', "Registrant contact not disclosed")

                # Handle redacted data
                if "REDACTED" in registrant_name or "not disclosed" in registrant_name.lower():
                    registrant_name = "REDACTED FOR PRIVACY"

                # Introduce a delay between requests
                time.sleep(delay_between_requests)  # Delay between requests
                return domain, registrar, registrant_name

            except (whois.parser.PywhoisError, socket.timeout):
                if attempt < retries - 1:
                    # Exponential backoff on failure
                    time.sleep(2 ** attempt)
                    continue
                return domain, "Lookup failed", "Registrant contact not found"
            except Exception as e:
                return domain, f"Error: {str(e)}", "Registrant contact not found"


class WhoisLookupApp(QWidget):
    def __init__(self):
        super().__init__()

        # Window setup
        self.setWindowTitle("WHOIS Lookup Tool")
        self.setGeometry(100, 100, 800, 600)

        # Layout setup
        self.layout = QVBoxLayout()

        # Domain input area
        self.text_area = QTextEdit(self)
        self.text_area.setPlaceholderText("Enter domain names (one per line)...")
        self.layout.addWidget(self.text_area)

        # Buttons
        self.file_button = QPushButton("Load Domains from File", self)
        self.file_button.clicked.connect(self.load_domains)
        self.layout.addWidget(self.file_button)

        self.lookup_button = QPushButton("Start WHOIS Lookup", self)
        self.lookup_button.clicked.connect(self.start_lookup)
        self.layout.addWidget(self.lookup_button)

        # Progress bar
        self.progress = QProgressBar(self)
        self.layout.addWidget(self.progress)

        # Table for results
        self.table = QTableWidget(self)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Domain", "Registrar", "Registrant Name"])
        self.layout.addWidget(self.table)

        # Buttons for clearing and saving
        self.clear_button = QPushButton("Clear Input and Results", self)
        self.clear_button.clicked.connect(self.clear_text)
        self.layout.addWidget(self.clear_button)

        self.save_button = QPushButton("Save Results to CSV", self)
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)  # Disable until results are available
        self.layout.addWidget(self.save_button)

        # Set layout
        self.setLayout(self.layout)

        # Initialize state variables
        self.domains = []
        self.results = []
        self.threads = []  # List to hold threads

    def clear_text(self):
        """Clear the input and results text boxes"""
        self.text_area.clear()
        self.table.setRowCount(0)

    def load_domains(self):
        """Load domain names from a text file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Domain List", "", "Text files (*.txt)")
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.domains = [line.strip() for line in f.readlines() if line.strip()]
            self.text_area.setPlainText("\n".join(self.domains))

    def start_lookup(self):
        """Trigger the WHOIS lookup process"""
        self.domains = self.text_area.toPlainText().splitlines()
        self.domains = [domain.strip() for domain in self.domains if domain.strip()]

        if not self.domains:
            QMessageBox.critical(self, "Error", "Please enter or load domain names.")
            return

        self.results = []
        self.progress.setValue(0)
        self.progress.setMaximum(len(self.domains))

        self.save_button.setEnabled(False)
        self.lookup_button.setEnabled(False)

        # Clear previous results in the table
        self.table.setRowCount(0)

        # Divide domains into batches for multiple threads
        num_threads = 3  # Can adjust this based on available system resources
        batch_size = math.ceil(len(self.domains) / num_threads)

        for i in range(0, len(self.domains), batch_size):
            batch = self.domains[i:i + batch_size]
            thread = WhoisLookupThread(batch)
            thread.result_signal.connect(self.update_results)
            thread.progress_signal.connect(self.update_progress)
            thread.finished.connect(self.on_lookup_finished)
            self.threads.append(thread)
            thread.start()

    def update_results(self, domain, registrar, registrant_name):
        """Update the table with new lookup info"""
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        self.table.setItem(row_position, 0, QTableWidgetItem(domain))
        self.table.setItem(row_position, 1, QTableWidgetItem(registrar))
        self.table.setItem(row_position, 2, QTableWidgetItem(registrant_name))

    def update_progress(self, value):
        """Update progress bar"""
        self.progress.setValue(self.progress.value() + value)

    def on_lookup_finished(self):
        """Called when lookup is finished"""
        all_finished = all([not thread.isRunning() for thread in self.threads])
        if all_finished:
            self.save_button.setEnabled(True)
            self.lookup_button.setEnabled(True)

    def save_results(self):
        """Save the lookup results to a CSV file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results to CSV", "", "CSV files (*.csv)")
        if file_path:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Domain", "Registrar", "Registrant Name"])
                writer.writerows(self.results)
            QMessageBox.information(self, "Success", f"Results saved to {file_path}")


# Main entry point for the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WhoisLookupApp()
    window.show()
    sys.exit(app.exec_())
