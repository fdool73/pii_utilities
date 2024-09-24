import os
import re
import json
import yaml
import random
import logging
import shutil

# Set up logging for debugging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("pii_tool")

# Updated regex patterns for PII detection
patterns = {
    'email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    # Regex for potential IP addresses (will validate after capture)
    'ip_address': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'aws_account': r'\b\d{12}\b',  # AWS Account numbers: exactly 12 digits
    'github_token': r'ghp_[A-Za-z0-9]{36}',
    'gitlab_token': r'glpat-[A-Za-z0-9-_]{20}',
    'aws_arn': r'arn:aws:[a-zA-Z0-9:_/.-]+',
    'gcp_project': r'projects/[a-zA-Z0-9-]+',
    'azure_resource': r'/subscriptions/[a-fA-F0-9-]+/resourceGroups/[a-zA-Z0-9-]+',
    # Full URLs starting with http or https
    'url': r'\bhttps?:\/\/[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,5}(\/[^\s]*)?\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',  # Social Security Number
    # US phone numbers (avoiding matching AWS account numbers)
    'phone_number': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    # Credit card: adjusted to avoid matching port numbers
    'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
    # Driver's license pattern with custom constraints
    'dl_number': r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{4,9}(?!.*([A-Za-z]){3})(?=.*\d{4})'
}

# Dummy data generation functions
dummy_data_generators = {
    'email': lambda: f"dummy{random.randint(1000, 9999)}@example.com",
    'ip_address': lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
    'aws_account': lambda: f"{random.randint(100000000000, 999999999999)}",
    'ssn': lambda: f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}",
    'phone_number': lambda: f"({random.randint(100, 999)}) {random.randint(100, 999)}-{random.randint(1000, 9999)}"
}

# Placeholders for anonymization
anonymize_placeholders = {
    'email': "<ANONYMIZED_EMAIL>",
    'ip_address': "<ANONYMIZED_IP_ADDRESS>",
    'aws_account': "<ANONYMIZED_AWS_ACCOUNT>",
    'ssn': "<ANONYMIZED_SSN>",
    'phone_number': "<ANONYMIZED_PHONE_NUMBER>",
}

# Validate whether the captured string is a valid IP address
def validate_ip_address(ip_address):
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            number = int(part)
            if number < 0 or number > 255:
                return False
        except ValueError:
            return False
    return True

# Generate report for PII found
def generate_report(pii_detected, file_path):
    report_file = "pii_report.txt"
    with open(report_file, 'a') as report:
        report.write(f"\nPII found in {file_path}:\n")
        for pii_type, matches in pii_detected.items():
            flattened_matches = [', '.join(match) if isinstance(match, tuple) else match for match in matches]
            report.write(f"  {pii_type.capitalize()} detected: {', '.join(flattened_matches)}\n")
    print(f"Report generated: {report_file}")

# Helper function to process content for PII identification, anonymization, or replacement
def process_content(content, mode='identify'):
    pii_found = {}
    for key, pattern in patterns.items():
        try:
            matches = re.findall(pattern, content)
            if matches:
                # Apply validation for IP addresses
                if key == 'ip_address':
                    matches = [match for match in matches if validate_ip_address(match)]
                # Handle anonymization
                if mode == 'anonymize' and key in anonymize_placeholders:
                    for match in matches:
                        placeholder = anonymize_placeholders[key]
                        content = content.replace(match, placeholder)  # Replace PII with placeholders
                # Handle replacement with dummy data
                elif mode == 'replace' and key in dummy_data_generators:
                    for match in matches:
                        dummy_value = dummy_data_generators[key]()
                        content = content.replace(match, dummy_value)  # Replace PII with dummy data
                pii_found[key] = matches
        except Exception as e:
            logger.error(f"Error processing pattern {key}: {e}")
    return content, pii_found

# Helper function to read and write files (DRY principle)
def handle_file(file_path, mode='identify'):
    ext = os.path.splitext(file_path)[1].lower()
    pii_detected = {}

    try:
        with open(file_path, 'r', errors='ignore') as file:
            if ext == '.json':
                data = json.load(file)
                data_str = json.dumps(data, indent=2)
            elif ext in ['.yaml', '.yml']:
                data = yaml.safe_load(file)
                data_str = yaml.dump(data)
            else:
                data_str = file.read()

            updated_content, pii_detected = process_content(data_str, mode)

        if mode == 'identify':
            if pii_detected:
                print(f"PII found in {file_path}:")
                for pii_type, matches in pii_detected.items():
                    flattened_matches = [', '.join(match) if isinstance(match, tuple) else match for match in matches]
                    print(f"  {pii_type.capitalize()} detected: {', '.join(flattened_matches)}")
                # Generate PII report
                generate_report(pii_detected, file_path)
            else:
                print(f"No PII found in {file_path}")

        # Save the original file and create a new one if anonymizing or replacing
        if mode in ['anonymize', 'replace']:
            # Backup the original file
            shutil.copy(file_path, file_path + ".backup")
            print(f"Original file saved as: {file_path}.backup")
            
            # Create a new file with anonymized or dummy data
            suffix = "_anonymized" if mode == 'anonymize' else "_dummy"
            new_file_path = f"{os.path.splitext(file_path)[0]}{suffix}{ext}"
            with open(new_file_path, 'w') as file:
                file.write(updated_content)
            print(f"New file saved as: {new_file_path}")

        return pii_detected
    except (OSError, IOError, json.JSONDecodeError, yaml.YAMLError) as e:
        logger.error(f"Error processing file {file_path}: {e}")
        return None

# Function to list and process directory contents with letter-based options
def traverse_directory(current_directory, mode='identify'):
    while True:
        file_paths = list_directory(current_directory)

        print("\nOptions:")
        print("1) Scan all files in this directory")
        print("2) Go back one directory ('..')")
        print("3) Return to the main menu")
        print("4) Exit")

        choice = input("\nChoose an option: ").strip()

        if choice == '4':  # Exit
            print("Exiting the PII Management Tool. Goodbye!")
            exit(0)  # End the script entirely
        elif choice == '3':  # Return to the main menu
            return  # Break out of this function, returning to the main menu
        elif choice == '2':  # Go back one directory
            current_directory = os.path.dirname(current_directory)
        elif choice == '1':  # Scan all files in this directory
            process_all_files_in_directory(current_directory, mode)
            print(f"Processed all files in {current_directory}")
        elif choice.isalpha() and choice in [chr(i) for i in range(ord('a'), ord('a') + len(file_paths))]:  # Select a file or directory by letter
            selected_path = file_paths[ord(choice) - ord('a')]
            if os.path.isfile(selected_path):  # If a file is selected, process it
                handle_file(selected_path, mode)
                print(f"Processed {selected_path}")
            elif os.path.isdir(selected_path):  # If a directory is selected, enter it
                current_directory = selected_path
        else:
            print(f"'{choice}' is not a valid option. Please try again.")

# Helper function to list files and directories with letters
def list_directory(directory):
    print(f"\nListing contents of directory: {directory}")

    file_paths = []
    entries = sorted(os.scandir(directory), key=lambda e: (not e.is_dir(), e.name.lower()))
    
    for index, entry in enumerate(entries, start=0):
        entry_type = "DIR " if entry.is_dir() else "FILE"
        letter = chr(ord('a') + index)
        print(f"[{letter}] {entry_type}: {entry.name}")
        file_paths.append(entry.path)

    return file_paths

# Function to traverse and process all files in a directory
def process_all_files_in_directory(directory, mode):
    for root, dirs, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"Processing file: {file_path}")
            handle_file(file_path, mode)

# Function to handle user's selection from a file or directory
def handle_directory_menu_choice(mode):
    current_directory = os.getcwd()
    traverse_directory(current_directory, mode)

# Function to map user's choice to the appropriate mode
def get_mode_from_choice(choice):
    mode_map = {
        '1': 'identify',
        '2': 'anonymize',
        '3': 'replace',
        '4': 'identify',
        '5': 'anonymize',
        '6': 'replace'
    }
    return mode_map.get(choice)

# Main menu system for interacting with the user
def menu():
    print("\n--- PII Management Tool ---")
    print("[1] Identify PII in a file or directory")
    print("[2] Anonymize PII in a file or directory (replace with placeholders)")
    print("[3] Replace PII in a file or directory with dummy data")
    print("[4] Exit")

# Function to get user input
def user_input(prompt):
    return input(prompt).strip()

# Refactored main function with reduced complexity
def main():
    while True:
        menu()
        choice = user_input("\nEnter your choice: ")

        if choice == '4':
            print("Exiting the PII Management Tool. Goodbye!")
            break

        if choice in ['1', '2', '3']:
            mode = get_mode_from_choice(choice)
            handle_directory_menu_choice(mode)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
