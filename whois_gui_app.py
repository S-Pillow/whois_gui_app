import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QProgressBar,
    QFileDialog, QTableWidget, QTableWidgetItem, QMessageBox, QCheckBox, QHBoxLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
import whois
import csv
import socket
import time


class WhoisLookupThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, str, str, str, str)

    def __init__(self, domains, include_domain, include_registrar, include_registrant, include_status):
        super().__init__()
        self.domains = domains
        self.include_domain = include_domain
        self.include_registrar = include_registrar
        self.include_registrant = include_registrant
        self.include_status = include_status

    def run(self):
        for domain in self.domains:
            domain, registrar, registrant_name, status_string_gui, status_string_csv = self.perform_whois_lookup(domain)
            self.result_signal.emit(domain, registrar, registrant_name, status_string_gui, status_string_csv)
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

                # Get the statuses and ensure they're formatted correctly
                statuses = w.get('status', ["No status found"])
                if isinstance(statuses, list):
                    # Trim each status and store them in a list
                    trimmed_statuses = [status.split("#")[-1] for status in statuses]
                else:
                    trimmed_statuses = [statuses.split("#")[-1]]

                # Create status strings for GUI and CSV
                status_string_gui = "\n".join(trimmed_statuses)  # For GUI (newlines)
                status_string_csv = ", ".join(trimmed_statuses)  # For CSV (commas)

                # Handle redacted data
                if "REDACTED" in registrant_name or "not disclosed" in registrant_name.lower():
                    registrant_name = "REDACTED FOR PRIVACY"

                # Introduce a delay between requests
                time.sleep(delay_between_requests)  # Delay between requests
                return domain, registrar, registrant_name, status_string_gui, status_string_csv

            except (whois.parser.PywhoisError, socket.timeout):
                if attempt < retries - 1:
                    # Exponential backoff on failure
                    time.sleep(2 ** attempt)
                    continue
                return domain, "Lookup failed", "Registrant contact not found", "No status found", "No status found"
            except Exception as e:
                return domain, f"Error: {str(e)}", "Registrant contact not found", "No status found", "No status found"


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

        # Checkboxes for columns
        self.checkbox_layout = QHBoxLayout()
        self.domain_checkbox = QCheckBox("Domain Name", self)
        self.domain_checkbox.setChecked(True)
        self.checkbox_layout.addWidget(self.domain_checkbox)

        self.registrar_checkbox = QCheckBox("Registrar", self)
        self.registrar_checkbox.setChecked(True)
        self.checkbox_layout.addWidget(self.registrar_checkbox)

        self.registrant_checkbox = QCheckBox("Registrant Name", self)
        self.registrant_checkbox.setChecked(True)
        self.checkbox_layout.addWidget(self.registrant_checkbox)

        self.status_checkbox = QCheckBox("Status", self)
        self.status_checkbox.setChecked(True)
        self.checkbox_layout.addWidget(self.status_checkbox)

        self.layout.addLayout(self.checkbox_layout)

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
        self.results = []
        self.progress.setValue(0)
        self.save_button.setEnabled(False)

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

        # Set table columns based on checked boxes
        headers = []
        if self.domain_checkbox.isChecked():
            headers.append("Domain")
        if self.registrar_checkbox.isChecked():
            headers.append("Registrar")
        if self.registrant_checkbox.isChecked():
            headers.append("Registrant Name")
        if self.status_checkbox.isChecked():
            headers.append("Status")

        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)

        # Start thread for lookup
        thread = WhoisLookupThread(
            self.domains,
            self.domain_checkbox.isChecked(),
            self.registrar_checkbox.isChecked(),
            self.registrant_checkbox.isChecked(),
            self.status_checkbox.isChecked(),
        )
        thread.result_signal.connect(self.update_results)
        thread.progress_signal.connect(self.update_progress)
        thread.finished.connect(self.on_lookup_finished)
        self.threads.append(thread)
        thread.start()

    def update_results(self, domain, registrar, registrant_name, status_string_gui, status_string_csv):
        """Update the table with new lookup info"""
        # Store the CSV status string for later use
        self.results.append((domain, registrar, registrant_name, status_string_csv))

        row_position = self.table.rowCount()
        self.table.insertRow(row_position)
        col_position = 0

        if self.domain_checkbox.isChecked():
            self.table.setItem(row_position, col_position, QTableWidgetItem(domain))
            col_position += 1
        if self.registrar_checkbox.isChecked():
            self.table.setItem(row_position, col_position, QTableWidgetItem(registrar))
            col_position += 1
        if self.registrant_checkbox.isChecked():
            self.table.setItem(row_position, col_position, QTableWidgetItem(registrant_name))
            col_position += 1
        if self.status_checkbox.isChecked():
            item = QTableWidgetItem(status_string_gui)
            item.setTextAlignment(Qt.AlignLeft | Qt.AlignTop)
            self.table.setItem(row_position, col_position, item)
            self.table.resizeRowToContents(row_position)
        self.table.resizeColumnsToContents()

    def update_progress(self, value):
        """Update progress bar"""
        self.progress.setValue(self.progress.value() + value)

    def on_lookup_finished(self):
        """Called when lookup is finished"""
        self.save_button.setEnabled(True)
        self.lookup_button.setEnabled(True)

    def save_results(self):
        """Save the lookup results to a CSV file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Results to CSV", "", "CSV files (*.csv)")
        if file_path:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                headers = []
                if self.domain_checkbox.isChecked():
                    headers.append("Domain")
                if self.registrar_checkbox.isChecked():
                    headers.append("Registrar")
                if self.registrant_checkbox.isChecked():
                    headers.append("Registrant Name")
                if self.status_checkbox.isChecked():
                    headers.append("Status")
                writer.writerow(headers)

                for result in self.results:
                    row_data = []
                    if self.domain_checkbox.isChecked():
                        row_data.append(result[0])
                    if self.registrar_checkbox.isChecked():
                        row_data.append(result[1])
                    if self.registrant_checkbox.isChecked():
                        row_data.append(result[2])
                    if self.status_checkbox.isChecked():
                        row_data.append(result[3])  # status_string_csv
                    writer.writerow(row_data)

            QMessageBox.information(self, "Success", f"Results saved to {file_path}")


# Main entry point for the application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WhoisLookupApp()
    window.show()
    sys.exit(app.exec_())
