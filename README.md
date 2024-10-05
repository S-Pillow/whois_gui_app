# WHOIS Lookup Tool

This Python application performs WHOIS lookups on domain names to retrieve their registrar, registrant, and status information. It features a GUI built with PyQt5, batch processing, and options for selecting specific fields to query and display.

## Features

- **PyQt5 GUI**: A user-friendly interface with checkboxes for selecting specific WHOIS fields.
- **Selectable Fields**: Users can choose to include the following fields in the output:
  - Domain Name
  - Registrar
  - Registrant Name
  - Status (with support for multiple statuses per domain)
- **Batch WHOIS Lookups**: Perform WHOIS queries in batches with customizable delay to avoid rate-limiting by registries.
- **Save Results to CSV**: The results can be saved to a CSV file.
- **Dynamic Table Resizing**: Output table resizes dynamically based on the selected fields and returned data.

## Installation

### For Python Users

1. Clone this repository or download the source code.
2. Install the required dependencies by running:

    ```bash
    pip install python-whois PyQt5
    ```

### For Standalone EXE Users

If you prefer not to install Python or dependencies, you can use the standalone EXE version of the tool (available in the [Releases](#) section).

## How to Use

### Run the Application

- If you're using the Python version, run the `whois_gui_app.py` script.
- If you're using the EXE, just double-click the EXE file.

### Input Domains

- Manually enter domains in the text area, one per line, or load a list of domains from a text file using the "Load Domains from File" button.

### Select Fields

- Check or uncheck the fields you want to query from WHOIS (Domain, Registrar, Registrant Name, Status).

### Start WHOIS Lookup

- Click the "Start WHOIS Lookup" button to begin querying the WHOIS data. The progress bar will update as the lookups complete.

### View and Save Results

- View the results in the table, which will dynamically adjust based on the selected fields and the returned data.
- Use the "Save Results to CSV" button to export the results to a CSV file.

### Clear Data

- Use the "Clear Input and Results" button to reset the application for a new lookup.

## Known Limitations

- WHOIS lookups for certain domain registries (e.g., those managed by GoDaddy) may have rate-limits, so the application handles this by adding a delay between requests.
- The Status field may return multiple entries, which are displayed vertically in the table.



## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
