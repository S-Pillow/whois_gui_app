import sys
import time
import whois
import socket
import csv  # Importing the csv module
from PyQt5 import QtWidgets, QtCore

class WhoisLookupApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.domains = []
        self.results = []

        # Set up the GUI components
        self.init_ui()

    def init_ui(self):
        # Set default window size
        self.setGeometry(100, 100, 800, 600)  # Set a default window width of 800 and height of 600

        # Set up the layout
        layout = QtWidgets.QVBoxLayout()

        # Text area for domain input
        self.text_area = QtWidgets.QPlainTextEdit(self)
        self.text_area.setPlaceholderText("Enter domains here, one per line...")
        layout.addWidget(self.text_area)

        # Horizontal layout for checkboxes
        checkbox_layout = QtWidgets.QHBoxLayout()

        # Checkboxes for selecting WHOIS fields
        self.checkbox_domain = QtWidgets.QCheckBox("Domain Name", self)
        self.checkbox_domain.setChecked(True)
        self.checkbox_registrar = QtWidgets.QCheckBox("Registrar", self)
        self.checkbox_registrar.setChecked(True)
        self.checkbox_registrant = QtWidgets.QCheckBox("Registrant Name", self)
        self.checkbox_registrant.setChecked(True)

        # Add checkboxes to the horizontal layout
        checkbox_layout.addWidget(self.checkbox_domain)
        checkbox_layout.addWidget(self.checkbox_registrar)
        checkbox_layout.addWidget(self.checkbox_registrant)

        # Add checkbox layout to the main layout
        layout.addLayout(checkbox_layout)

        # Button to load domains from file
        self.file_button = QtWidgets.QPushButton("Load Domains from File", self)
        self.file_button.clicked.connect(self.load_domains)
        layout.addWidget(self.file_button)

        # Button to start lookup
        self.lookup_button = QtWidgets.QPushButton("Start WHOIS Lookup", self)
        self.lookup_button.clicked.connect(self.start_lookup)
        layout.addWidget(self.lookup_button)

        # Progress bar
        self.progress_bar = QtWidgets.QProgressBar(self)
        layout.addWidget(self.progress_bar)

        # Table to display results
        self.results_table = QtWidgets.QTableWidget(self)
        layout.addWidget(self.results_table)

        # Button to clear input and results
        self.clear_button = QtWidgets.QPushButton("Clear Input and Results", self)
        self.clear_button.clicked.connect(self.clear_text)
        layout.addWidget(self.clear_button)

        # Button to save results to CSV
        self.save_button = QtWidgets.QPushButton("Save Results to CSV", self)
        self.save_button.clicked.connect(self.save_results)
        layout.addWidget(self.save_button)

        # Set the layout to the QWidget
        self.setLayout(layout)
        self.setWindowTitle("WHOIS Lookup Tool")

    def clear_text(self):
        """Clear the input and results text boxes."""
        self.text_area.clear()
        self.results_table.setRowCount(0)

    def load_domains(self):
        """Load domain names from a text file."""
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open Domain List", "",
                                                            "Text Files (*.txt);;All Files (*)", options=options)
        if file_path:
            with open(file_path, "r", encoding='utf-8') as f:
                self.domains = [line.strip() for line in f.readlines() if line.strip()]
            self.text_area.setPlainText("\n".join(self.domains))

    def start_lookup(self):
        """Trigger the WHOIS lookup process."""
        self.domains = self.text_area.toPlainText().splitlines()
        self.domains = [domain.strip() for domain in self.domains if domain.strip()]

        if not self.domains:
            QtWidgets.QMessageBox.critical(self, "Error", "Please enter or load domain names.")
            return

        self.results = []
        self.results_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(self.domains))

        # Determine which checkboxes are selected
        self.selected_fields = {
            "domain": self.checkbox_domain.isChecked(),
            "registrar": self.checkbox_registrar.isChecked(),
            "registrant": self.checkbox_registrant.isChecked()
        }

        # Set up the table headers based on selected checkboxes
        self.setup_table_headers()

        # Perform WHOIS lookup in batches
        self.worker = WhoisWorker(self.domains, self.selected_fields)
        self.worker.update_table_signal.connect(self.update_results)
        self.worker.update_progress_signal.connect(self.update_progress)
        self.worker.finished.connect(self.on_lookup_finished)

        self.lookup_button.setEnabled(False)
        self.worker.start()

    def setup_table_headers(self):
        """Set up the table headers based on selected fields."""
        headers = []
        if self.selected_fields["domain"]:
            headers.append("Domain Name")
        if self.selected_fields["registrar"]:
            headers.append("Registrar")
        if self.selected_fields["registrant"]:
            headers.append("Registrant Name")

        self.results_table.setColumnCount(len(headers))
        self.results_table.setHorizontalHeaderLabels(headers)

    def update_results(self, data):
        """Update the results table with new lookup info."""
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)

        column = 0
        if self.selected_fields["domain"]:
            self.results_table.setItem(row_position, column, QtWidgets.QTableWidgetItem(data["domain"]))
            column += 1
        if self.selected_fields["registrar"]:
            self.results_table.setItem(row_position, column, QtWidgets.QTableWidgetItem(data["registrar"]))
            column += 1
        if self.selected_fields["registrant"]:
            self.results_table.setItem(row_position, column, QtWidgets.QTableWidgetItem(data["registrant"]))

    def update_progress(self, progress_value):
        """Update the progress bar."""
        self.progress_bar.setValue(progress_value)

    def on_lookup_finished(self):
        """Re-enable the lookup button once lookup is done."""
        self.lookup_button.setEnabled(True)

    def save_results(self):
        """Save the lookup results to a CSV file."""
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Results to CSV", "",
                                                            "CSV Files (*.csv);;All Files (*)", options=options)
        if file_path:
            with open(file_path, "w", newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                headers = []
                if self.selected_fields["domain"]:
                    headers.append("Domain Name")
                if self.selected_fields["registrar"]:
                    headers.append("Registrar")
                if self.selected_fields["registrant"]:
                    headers.append("Registrant Name")
                writer.writerow(headers)
                for i in range(self.results_table.rowCount()):
                    row = []
                    if self.selected_fields["domain"]:
                        row.append(self.results_table.item(i, 0).text())
                    if self.selected_fields["registrar"]:
                        row.append(self.results_table.item(i, 1).text())
                    if self.selected_fields["registrant"]:
                        row.append(self.results_table.item(i, 2).text())
                    writer.writerow(row)
            QtWidgets.QMessageBox.information(self, "Success", f"Results saved to {file_path}")

class WhoisWorker(QtCore.QThread):
    update_table_signal = QtCore.pyqtSignal(dict)
    update_progress_signal = QtCore.pyqtSignal(int)

    def __init__(self, domains, selected_fields, batch_size=20, delay_between_batches=10):
        super().__init__()
        self.domains = domains
        self.selected_fields = selected_fields
        self.batch_size = batch_size
        self.delay_between_batches = delay_between_batches

    def run(self):
        """Run the WHOIS lookup in batches."""
        total_domains = len(self.domains)
        num_batches = (total_domains + self.batch_size - 1) // self.batch_size  # Calculate the number of batches

        for batch_num in range(num_batches):
            # Get the current batch of domains
            start_index = batch_num * self.batch_size
            end_index = min(start_index + self.batch_size, total_domains)
            batch_domains = self.domains[start_index:end_index]

            # Perform the lookup for the current batch
            for domain in batch_domains:
                data = self.perform_whois_lookup(domain)
                self.update_table_signal.emit(data)
                progress_value = start_index + batch_domains.index(domain) + 1
                self.update_progress_signal.emit(progress_value)

            # Introduce a delay between batches to avoid rate-limiting
            if batch_num < num_batches - 1:  # Avoid delay after the last batch
                time.sleep(self.delay_between_batches)

    def perform_whois_lookup(self, domain, timeout=10):
        """Perform WHOIS lookup for a single domain with a timeout."""
        try:
            socket.setdefaulttimeout(timeout)
            w = whois.whois(domain)

            data = {}
            if self.selected_fields["domain"]:
                data["domain"] = domain
            if self.selected_fields["registrar"]:
                data["registrar"] = w.registrar or "Registrar not found"
            if self.selected_fields["registrant"]:
                data["registrant"] = w.get('registrant_name', "Registrant contact not found")

            return data
        except Exception as e:
            return {
                "domain": domain,
                "registrar": "Error during WHOIS lookup",
                "registrant": f"Error: {str(e)}"
            }

# Main loop for the PyQt app
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = WhoisLookupApp()
    window.show()
    sys.exit(app.exec_())
