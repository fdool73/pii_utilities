import os
import re
import json
import yaml
import random
import logging
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PIIPattern:
    """Dataclass to store PII pattern information"""
    pattern: str
    placeholder: str
    dummy_generator: callable = None

class PIIPatterns:
    """Class to manage PII detection patterns"""
    
    def __init__(self):
        self.patterns: Dict[str, PIIPattern] = {
            # Contact Information
            'email': PIIPattern(
                pattern=r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
                placeholder='<ANONYMIZED_EMAIL>',
                dummy_generator=lambda: f"dummy{random.randint(1000,9999)}@example.com"
            ),
            'phone_number': PIIPattern(
                pattern=r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
                placeholder='<ANONYMIZED_PHONE>',
                dummy_generator=lambda: f"({random.randint(100,999)}) {random.randint(100,999)}-{random.randint(1000,9999)}"
            ),
            
            # Repository and Project Information
            'github_repo': PIIPattern(
                pattern=r'(?:https?://)?(?:www\.)?github\.com/[\w.-]+/[\w.-]+',
                placeholder='<ANONYMIZED_GITHUB_REPO>'
            ),
            'gitlab_repo': PIIPattern(
                pattern=r'(?:https?://)?(?:www\.)?gitlab\.com/[\w.-]+/[\w.-]+',
                placeholder='<ANONYMIZED_GITLAB_REPO>'
            ),
            'private_repo': PIIPattern(
                # Matches internal/private repository URLs
                pattern=r'(?:https?://)?(?:[\w.-]+@)?[\w.-]+\.(?:org|com|net|io)/[\w.-]+/[\w.-]+(?:\.git)?',
                placeholder='<ANONYMIZED_PRIVATE_REPO>'
            ),
            'project_id': PIIPattern(
                # Common project ID patterns (adjust based on your needs)
                pattern=r'\b(?:proj|project|prj)-[a-zA-Z0-9-_]+\b',
                placeholder='<ANONYMIZED_PROJECT_ID>'
            ),
            
            # Authentication Tokens and Keys
            'github_token': PIIPattern(
                # GitHub PAT and OAuth tokens
                pattern=r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}',
                placeholder='<ANONYMIZED_GITHUB_TOKEN>'
            ),
            'gitlab_token': PIIPattern(
                # GitLab PAT and other tokens
                pattern=r'glpat-[A-Za-z0-9-_]{20}|glpat-[A-Za-z0-9-_]{50}',
                placeholder='<ANONYMIZED_GITLAB_TOKEN>'
            ),
            'api_key': PIIPattern(
                pattern=r'(?i)(?:api[_-]?key|apikey|api[_-]?token)["\']?\s*(?::|=>|=)\s*["\']?[a-zA-Z0-9._-]{20,}["\']?',
                placeholder='<ANONYMIZED_API_KEY>'
            ),
            'jwt_token': PIIPattern(
                pattern=r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                placeholder='<ANONYMIZED_JWT>'
            ),
            'ssh_key': PIIPattern(
                pattern=r'(?i)-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY[^"]+END\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
                placeholder='<ANONYMIZED_SSH_KEY>'
            ),
            
            # Cloud Service Information
            'aws_account': PIIPattern(
                pattern=r'\b\d{12}\b',
                placeholder='<ANONYMIZED_AWS_ACCOUNT>',
                dummy_generator=lambda: f"{random.randint(100000000000,999999999999)}"
            ),
            'aws_arn': PIIPattern(
                pattern=r'arn:aws:[a-zA-Z0-9:\/_.-]+',
                placeholder='<ANONYMIZED_AWS_ARN>'
            ),
            'aws_access_key': PIIPattern(
                pattern=r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
                placeholder='<ANONYMIZED_AWS_ACCESS_KEY>'
            ),
            'aws_secret_key': PIIPattern(
                pattern=r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
                placeholder='<ANONYMIZED_AWS_SECRET_KEY>'
            ),
            'azure_connection': PIIPattern(
                pattern=r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net',
                placeholder='<ANONYMIZED_AZURE_CONNECTION>'
            ),
            
            # Infrastructure Information
            'ip_address': PIIPattern(
                pattern=r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                placeholder='<ANONYMIZED_IP>',
                dummy_generator=lambda: '.'.join(str(random.randint(1,255)) for _ in range(4))
            ),
            'internal_url': PIIPattern(
                # Matches internal domain patterns
                pattern=r'(?:https?://)?(?:[\w-]+\.)*(?:internal|local|dev|staging|test|prod)\.[\w-]+\.(?:com|org|net|io)',
                placeholder='<ANONYMIZED_INTERNAL_URL>'
            ),
            'mac_address': PIIPattern(
                pattern=r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b',
                placeholder='<ANONYMIZED_MAC>'
            ),
            'hostname': PIIPattern(
                pattern=r'\b(?:ip|host|server|node|instance|vm)-[a-zA-Z0-9-]+\b',
                placeholder='<ANONYMIZED_HOSTNAME>'
            ),
            
            # Personal Information
            'ssn': PIIPattern(
                pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                placeholder='<ANONYMIZED_SSN>',
                dummy_generator=lambda: f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
            ),
            'credit_card': PIIPattern(
                pattern=r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                placeholder='<ANONYMIZED_CC>'
            ),
            'password': PIIPattern(
                pattern=r'(?i)(?:password|passwd|pwd)["\']?\s*(?::|=>|=)\s*["\']?[^"\'\s]{8,}["\']?',
                placeholder='<ANONYMIZED_PASSWORD>'
            ),
            'database_url': PIIPattern(
                pattern=r'(?i)(?:jdbc|mongodb|postgresql|mysql)://[^\s<>"]+',
                placeholder='<ANONYMIZED_DB_URL>'
            )
        }

class FileHandler(ABC):
    """Abstract base class for file handlers"""
    
    @abstractmethod
    def read(self, file_path: Path) -> str:
        pass
        
    @abstractmethod
    def write(self, file_path: Path, content: str):
        pass

class TextFileHandler(FileHandler):
    """Handler for plain text files"""
    
    def read(self, file_path: Path) -> str:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
            
    def write(self, file_path: Path, content: str):
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

class JsonFileHandler(FileHandler):
    """Handler for JSON files"""
    
    def read(self, file_path: Path) -> str:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Preserve the original formatting by reading as string first
            content = f.read()
            # Validate it's proper JSON
            json.loads(content)
            return content
            
    def write(self, file_path: Path, content: str):
        with open(file_path, 'w', encoding='utf-8') as f:
            # Validate and format the JSON while preserving structure
            f.write(json.dumps(json.loads(content), indent=2))

class YamlFileHandler(FileHandler):
    """Handler for YAML files"""
    
    def read(self, file_path: Path) -> str:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Preserve the original formatting by reading as string first
            content = f.read()
            # Validate it's proper YAML
            yaml.safe_load(content)
            return content
            
    def write(self, file_path: Path, content: str):
        with open(file_path, 'w', encoding='utf-8') as f:
            # Write the content directly to preserve formatting
            # but first validate it's proper YAML
            yaml.safe_load(content)
            f.write(content)

class PIIProcessor:
    """Main class for PII processing operations"""
    
    def __init__(self):
        self.patterns = PIIPatterns()
        self._file_handlers = {
            '.txt': TextFileHandler(),
            '.json': JsonFileHandler(),
            '.yaml': YamlFileHandler(),
            '.yml': YamlFileHandler()
        }
        
    def _get_file_handler(self, file_path: Path) -> FileHandler:
        """Get appropriate file handler based on file extension"""
        ext = file_path.suffix.lower()
        handler = self._file_handlers.get(ext)
        if not handler:
            raise ValueError(f"Unsupported file type: {ext}")
        return handler
        
    def process_file(self, file_path: Union[str, Path], mode: str = 'identify') -> Dict[str, List[str]]:
        """Process a single file for PII"""
        file_path = Path(file_path)
        handler = self._get_file_handler(file_path)
        
        try:
            original_content = handler.read(file_path)
            pii_found = {}
            processed_content = original_content
            
            # Process content based on mode
            if mode in ['anonymize', 'replace']:
                # Create a mapping of PII to replacements to ensure consistency
                replacements = {}
                
                # First pass: identify all PII and prepare replacements
                for pii_type, pattern in self.patterns.patterns.items():
                    matches = re.finditer(pattern.pattern, processed_content)
                    found_matches = []
                    
                    for match in matches:
                        found_text = match.group(0)
                        found_matches.append(found_text)
                        
                        # Create consistent replacement if not already assigned
                        if found_text not in replacements:
                            replacement = (
                                pattern.dummy_generator() if mode == 'replace' and pattern.dummy_generator
                                else pattern.placeholder
                            )
                            replacements[found_text] = replacement
                    
                    if found_matches:
                        pii_found[pii_type] = found_matches
                
                # Second pass: replace all PII instances while preserving structure
                for original, replacement in replacements.items():
                    processed_content = processed_content.replace(original, replacement)
                
                # Save processed content
                new_suffix = '_anonymized' if mode == 'anonymize' else '_dummy'
                new_path = file_path.with_stem(f"{file_path.stem}{new_suffix}")
                handler.write(new_path, processed_content)
                logger.info(f"Processed file saved as: {new_path}")
                
            else:  # identify mode
                for pii_type, pattern in self.patterns.patterns.items():
                    matches = re.findall(pattern.pattern, processed_content)
                    if matches:
                        pii_found[pii_type] = matches
            
            return pii_found
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            raise

    def process_directory(self, directory: Union[str, Path], mode: str = 'identify') -> Dict[Path, Dict[str, List[str]]]:
        """Process all supported files in a directory"""
        directory = Path(directory)
        results = {}
        
        for file_path in directory.rglob('*'):
            if file_path.suffix.lower() in self._file_handlers:
                try:
                    results[file_path] = self.process_file(file_path, mode)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
                    results[file_path] = {"error": str(e)}
                    
        return results

    def generate_report(self, results: Dict[Path, Dict[str, List[str]]], output_file: Union[str, Path]):
        """Generate a detailed report of PII findings"""
        output_file = Path(output_file)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("PII Detection Report\n")
            f.write("===================\n")
            f.write(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            total_files = len(results)
            files_with_pii = sum(1 for pii_found in results.values() if pii_found)
            
            f.write(f"Summary:\n")
            f.write(f"- Total files scanned: {total_files}\n")
            f.write(f"- Files containing PII: {files_with_pii}\n\n")
            
            for file_path, pii_found in results.items():
                f.write(f"\nFile: {file_path}\n")
                f.write("=" * (len(str(file_path)) + 6) + "\n")
                
                if not pii_found:
                    f.write("No PII detected in this file\n")
                    continue
                
                for pii_type, matches in pii_found.items():
                    if pii_type == "error":
                        f.write(f"Error processing file: {matches}\n")
                        continue
                        
                    f.write(f"\n{pii_type.upper()} ({len(matches)} instances):\n")
                    f.write("-" * (len(pii_type) + 15) + "\n")
                    
                    # Create a set to track unique instances
                    unique_matches = set(matches)
                    
                    for idx, match in enumerate(unique_matches, 1):
                        count = matches.count(match)
                        count_str = f" (appears {count} times)" if count > 1 else ""
                        f.write(f"{idx}. {match}{count_str}\n")
                    
                f.write("\n" + "-" * 80 + "\n")

class FileBrowser:
    """Interactive file browser for selecting files and directories"""
    
    def __init__(self):
        self.current_path = Path.cwd()
        
    def _list_contents(self) -> List[Tuple[str, Path]]:
        """List contents of current directory with letter indices"""
        contents = []
        
        # Add parent directory option if not at root
        if self.current_path != self.current_path.root:
            contents.append(("Parent directory", self.current_path.parent))
            
        # Add directories first, then files
        for item in sorted(self.current_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            item_type = "Directory" if item.is_dir() else "File"
            contents.append((f"{item_type}: {item.name}", item))
            
        return contents
        
    def _display_menu(self, contents: List[Tuple[str, Path]]):
        """Display the file browser menu"""
        print(f"\nCurrent directory: {self.current_path}")
        print("\nOptions:")
        
        for idx, (display_name, _) in enumerate(contents):
            print(f"{idx + 1}. {display_name}")
            
        print("\nq. Return to main menu")
        
    def browse(self) -> Optional[Path]:
        """Start the interactive file browser"""
        while True:
            contents = self._list_contents()
            self._display_menu(contents)
            
            choice = input("\nEnter your choice: ").lower().strip()
            
            if choice == 'q':
                return None
                
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(contents):
                    _, path = contents[idx]
                    
                    if path == self.current_path.parent:
                        self.current_path = path
                    elif path.is_dir():
                        self.current_path = path
                    else:
                        return path
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number or 'q'.")

def main():
    """Main CLI interface"""
    processor = PIIProcessor()
    file_browser = FileBrowser()
    
    while True:
        print("\nPII Management Tool")
        print("==================")
        print("1. Identify PII")
        print("2. Anonymize PII")
        print("3. Replace PII with dummy data")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '4':
            print("Goodbye!")
            break
            
        if choice not in ['1', '2', '3']:
            print("Invalid choice. Please try again.")
            continue
            
        mode = {
            '1': 'identify',
            '2': 'anonymize',
            '3': 'replace'
        }[choice]
        
        print("\nUse the file browser to select a file or directory")
        path = file_browser.browse()
        
        if path is None:
            continue
            
        try:
            if path.is_file():
                results = {path: processor.process_file(path, mode)}
                print(f"\nProcessing file: {path}")
            elif path.is_dir():
                print(f"\nProcessing directory: {path}")
                results = processor.process_directory(path, mode)
            else:
                print("Invalid path. Please try again.")
                continue
                
            # Generate report
            report_path = path.parent / f"pii_report_{path.stem}_{mode}.txt"
            processor.generate_report(results, report_path)
            print(f"\nReport generated: {report_path}")
            
            # Show summary with details
            print("\nSummary:")
            for file_path, pii_found in results.items():
                print(f"\n{file_path}:")
                if not pii_found:
                    print("  No PII detected")
                else:
                    for pii_type, matches in pii_found.items():
                        if pii_type != "error":
                            print(f"\n  {pii_type.upper()} ({len(matches)} instances):")
                            unique_matches = set(matches)
                            for match in unique_matches:
                                count = matches.count(match)
                                count_str = f" (appears {count} times)" if count > 1 else ""
                                print(f"    - {match}{count_str}")
                        else:
                            print(f"  Error: {matches}")
            
        except Exception as e:
            logger.error(f"Error: {e}")
            print(f"An error occurred: {e}")
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
