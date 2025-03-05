
#!/usr/bin/env python3
"""
Email Provider Analyzer

A Python script that analyzes email addresses from a CSV file and categorizes them by provider.
"""

import csv
import re
import sys
import argparse
from collections import Counter
import os.path

# Email validation regex
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# Domain to provider mapping
DOMAIN_PROVIDER_MAP = {
    # Google
    'gmail.com': 'Gmail',
    'googlemail.com': 'Gmail',
    'google.com': 'Google',
    
    # Microsoft
    'outlook.com': 'Outlook',
    'hotmail.com': 'Hotmail',
    'live.com': 'Microsoft',
    'msn.com': 'Microsoft',
    'microsoft.com': 'Microsoft',
    'office365.com': 'Microsoft',
    
    # Yahoo
    'yahoo.com': 'Yahoo',
    'yahoo.co.uk': 'Yahoo',
    'yahoo.co.jp': 'Yahoo',
    'yahoo.fr': 'Yahoo',
    'ymail.com': 'Yahoo',
    
    # Apple
    'icloud.com': 'iCloud',
    'me.com': 'Apple',
    'mac.com': 'Apple',
    'apple.com': 'Apple',
    
    # Proton
    'proton.me': 'Proton',
    'protonmail.com': 'Proton',
    'pm.me': 'Proton',
    
    # Yandex
    'yandex.ru': 'Yandex',
    'yandex.com': 'Yandex',
    
    # Mail.ru
    'mail.ru': 'Mail.ru',
    'inbox.ru': 'Mail.ru',
    'list.ru': 'Mail.ru',
    'bk.ru': 'Mail.ru',
    
    # Zoho
    'zoho.com': 'Zoho',
    'zohomail.com': 'Zoho',
    
    # AOL
    'aol.com': 'AOL',
    'aim.com': 'AOL',
    
    # GMX
    'gmx.com': 'GMX',
    'gmx.net': 'GMX',
    'gmx.de': 'GMX',
}

def get_provider_from_domain(domain):
    """Determine the provider based on the email domain."""
    # Check if domain is directly mapped
    if domain in DOMAIN_PROVIDER_MAP:
        return DOMAIN_PROVIDER_MAP[domain]
    
    # Check for custom domains used by major providers
    if any(keyword in domain for keyword in ['outlook', 'office', 'microsoft']):
        return 'Microsoft'
    
    if 'google' in domain:
        return 'Google'
    
    if 'yahoo' in domain:
        return 'Yahoo'
    
    if 'zoho' in domain:
        return 'Zoho'
    
    if 'yandex' in domain:
        return 'Yandex'
    
    if any(keyword in domain for keyword in ['proton', 'pm.me']):
        return 'Proton'
    
    # Return 'Other' for any unrecognized domain
    return 'Other'

def is_valid_email(email):
    """Check if the given string is a valid email address."""
    return bool(re.match(EMAIL_REGEX, email))

def analyze_csv(file_path, delimiter=','):
    """
    Analyze the CSV file to count email providers.
    
    Args:
        file_path: Path to the CSV file
        delimiter: CSV delimiter character
        
    Returns:
        A tuple containing (provider_counts, valid_count, invalid_count, emails_by_provider)
    """
    provider_counter = Counter()
    valid_emails = 0
    invalid_emails = 0
    emails_by_provider = {}
    
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csv_file:
            # Try to detect the dialect
            sample = csv_file.read(1024)
            csv_file.seek(0)
            
            sniffer = csv.Sniffer()
            try:
                dialect = sniffer.sniff(sample)
                has_header = sniffer.has_header(sample)
                reader = csv.DictReader(csv_file, dialect=dialect) if has_header else csv.reader(csv_file, dialect)
            except csv.Error:
                # Fall back to the provided delimiter if sniffing fails
                reader = csv.reader(csv_file, delimiter=delimiter)
            
            # Handle the expected columns format
            if has_header:
                # Check if we're working with the specified columns format
                if 'Email' in reader.fieldnames:
                    for row in reader:
                        email = row.get('Email', '').strip()
                        
                        if is_valid_email(email):
                            domain = email.split('@')[1].lower()
                            provider = get_provider_from_domain(domain)
                            
                            # Increment provider count
                            provider_counter[provider] += 1
                            
                            # Store email by provider
                            if provider not in emails_by_provider:
                                emails_by_provider[provider] = []
                            emails_by_provider[provider].append(email)
                            
                            valid_emails += 1
                        elif '@' in email:
                            # Probably a malformed email
                            invalid_emails += 1
                else:
                    # Generic CSV handling
                    for row in reader:
                        for field in row.values():
                            process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails)
            else:
                # No header, process each field in each row
                for row in reader:
                    for field in row:
                        process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails)
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when accessing '{file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)
        
    return provider_counter, valid_emails, invalid_emails, emails_by_provider

def process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails):
    """Process a single field to check if it's an email address."""
    # Clean the field
    email = str(field).strip().strip('"\'')
    
    if is_valid_email(email):
        domain = email.split('@')[1].lower()
        provider = get_provider_from_domain(domain)
        
        # Increment provider count
        provider_counter[provider] += 1
        
        # Store email by provider
        if provider not in emails_by_provider:
            emails_by_provider[provider] = []
        emails_by_provider[provider].append(email)
        
        valid_emails += 1
        return True
    elif '@' in email:
        # Probably a malformed email
        invalid_emails += 1
    
    return False

def get_default_output_path(input_file):
    """Generate a default output file path based on the input file."""
    directory = os.path.dirname(os.path.abspath(input_file))
    filename = os.path.basename(input_file)
    name_without_ext = os.path.splitext(filename)[0]
    return os.path.join(directory, f"{name_without_ext}_analysis.csv")

def print_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, verbose=False):
    """Print analysis results to console."""
    total_emails = valid_emails + invalid_emails
    
    print("\n===== EMAIL PROVIDER ANALYSIS =====")
    print(f"Total emails found: {total_emails}")
    print(f"Valid emails: {valid_emails}")
    print(f"Invalid emails: {invalid_emails}")
    print("\nPROVIDER BREAKDOWN:")
    
    # Get sorted providers by count (descending)
    sorted_providers = provider_counter.most_common()
    
    # Calculate the longest provider name for nice formatting
    max_provider_len = max([len(provider) for provider, _ in sorted_providers], default=10)
    
    # Print header
    print(f"\n{'PROVIDER':{max_provider_len}} | {'COUNT':6} | {'PERCENTAGE':10}")
    print("-" * (max_provider_len + 21))
    
    # Print provider statistics
    for provider, count in sorted_providers:
        percentage = (count / valid_emails) * 100 if valid_emails > 0 else 0
        print(f"{provider:{max_provider_len}} | {count:6} | {percentage:8.2f}%")
    
    # Print detailed breakdown if verbose mode is enabled
    if verbose:
        print("\nDETAILED EMAIL BREAKDOWN:")
        for provider, emails in emails_by_provider.items():
            print(f"\n{provider} ({len(emails)} emails):")
            for email in emails:
                print(f"  - {email}")

def export_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, output_file):
    """Export analysis results to a CSV file."""
    total_emails = valid_emails + invalid_emails
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write summary
            writer.writerow(['EMAIL PROVIDER ANALYSIS SUMMARY'])
            writer.writerow(['Total emails', total_emails])
            writer.writerow(['Valid emails', valid_emails])
            writer.writerow(['Invalid emails', invalid_emails])
            writer.writerow([])
            
            # Write provider breakdown
            writer.writerow(['PROVIDER BREAKDOWN'])
            writer.writerow(['Provider', 'Count', 'Percentage'])
            
            # Get sorted providers by count (descending)
            sorted_providers = provider_counter.most_common()
            
            # Write provider statistics
            for provider, count in sorted_providers:
                percentage = (count / valid_emails) * 100 if valid_emails > 0 else 0
                writer.writerow([provider, count, f"{percentage:.2f}%"])
            
            writer.writerow([])
            
            # Write detailed breakdown
            writer.writerow(['DETAILED EMAIL BREAKDOWN'])
            for provider, emails in emails_by_provider.items():
                writer.writerow([provider, f"({len(emails)} emails)"])
                for email in emails:
                    writer.writerow(['', email])
                writer.writerow([])
        
        print(f"\nResults exported to {output_file}")
    
    except Exception as e:
        print(f"Error exporting results: {e}")

def main():
    """Main function to parse arguments and run the analysis."""
    parser = argparse.ArgumentParser(description='Analyze email addresses from a CSV file by provider.')
    parser.add_argument('file', help='Path to the CSV file containing email addresses')
    parser.add_argument('-d', '--delimiter', default=',', help='CSV delimiter character (default: ,)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (list all emails)')
    parser.add_argument('-o', '--output', help='Export results to a CSV file (defaults to input_file_analysis.csv)')
    
    args = parser.parse_args()
    
    # Validate that the input file exists and is a CSV
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
    
    if not args.file.lower().endswith('.csv'):
        print(f"Warning: File '{args.file}' does not have a .csv extension. Proceeding anyway...")
    
    # Run the analysis
    provider_counter, valid_emails, invalid_emails, emails_by_provider = analyze_csv(
        args.file, delimiter=args.delimiter
    )
    
    # Print the results
    print_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, verbose=args.verbose)
    
    # Determine output path if not provided
    output_file = args.output if args.output else get_default_output_path(args.file)
    
    # Export the results
    export_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, output_file)
    print(f"\nResults automatically saved to: {output_file}")

if __name__ == '__main__':
    main()

