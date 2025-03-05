
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
import traceback

# Try to import dns.resolver for MX lookups
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

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
    
    # More providers...
    'yandex.ru': 'Yandex',
    'yandex.com': 'Yandex',
    'mail.ru': 'Mail.ru',
    'zoho.com': 'Zoho',
    'aol.com': 'AOL',
    'gmx.com': 'GMX',
    'gmx.net': 'GMX',
    'gmx.de': 'GMX',
}

# MX record to provider mapping
MX_PROVIDER_MAP = {
    'google': 'Google',
    'googlemail': 'Gmail',
    'gmail': 'Gmail',
    'outlook': 'Microsoft',
    'hotmail': 'Microsoft',
    'live': 'Microsoft', 
    'msn': 'Microsoft',
    'microsoft': 'Microsoft',
    'office365': 'Microsoft',
    'yahoodns': 'Yahoo',
    'yahoomail': 'Yahoo',
    'icloud': 'Apple',
    'me.com': 'Apple',
    'mail.me.com': 'Apple',
    'protonmail': 'Proton',
    'zoho': 'Zoho',
    'aol': 'AOL',
    'mail.ru': 'Mail.ru',
    'yandex': 'Yandex',
    'gmx': 'GMX',
}

# Cache for DNS MX lookups
MX_CACHE = {}

def get_provider_from_mx_records(domain):
    """Determine the provider from MX records."""
    if not DNS_AVAILABLE:
        return None
        
    # Check cache first
    if domain in MX_CACHE:
        return MX_CACHE[domain]
        
    provider = None
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_host = str(rdata.exchange).lower()
            
            # Check each part of the MX hostname against our provider mapping
            for mx_part in mx_host.split('.'):
                if mx_part in MX_PROVIDER_MAP:
                    provider = MX_PROVIDER_MAP[mx_part]
                    break
            
            if provider:
                break
                
    except Exception as e:
        print(f"DNS lookup error for {domain}: {e}")
        # Any DNS errors, just return None
        pass
        
    # Cache the result (even if None)
    MX_CACHE[domain] = provider
    return provider

def get_provider_from_domain(domain):
    """Determine the provider based on the email domain."""
    # First check our direct domain mapping
    if domain in DOMAIN_PROVIDER_MAP:
        return DOMAIN_PROVIDER_MAP[domain]
    
    # Check for custom domains used by major providers
    domain_lower = domain.lower()
    
    if 'outlook' in domain_lower or 'office' in domain_lower or 'microsoft' in domain_lower:
        return 'Microsoft'
    
    if 'google' in domain_lower:
        return 'Google'
    
    if 'yahoo' in domain_lower:
        return 'Yahoo'
    
    if 'zoho' in domain_lower:
        return 'Zoho'
    
    if 'yandex' in domain_lower:
        return 'Yandex'
    
    if 'proton' in domain_lower or 'pm.me' in domain_lower:
        return 'Proton'
    
    # Return 'Other' for any unrecognized domain
    return 'Other'

def is_valid_email(email):
    """Check if the given string is a valid email address."""
    return re.match(EMAIL_REGEX, email) is not None

def analyze_csv(file_path, delimiter=',', use_dns=True):
    """
    Analyze the CSV file to count email providers.
    
    Args:
        file_path: Path to the CSV file
        delimiter: CSV delimiter character
        use_dns: Whether to use DNS MX lookups for unknown domains
        
    Returns:
        A tuple containing (provider_counts, valid_count, invalid_count, emails_by_provider, original_rows, headers)
    """
    provider_counter = Counter()
    valid_emails = 0
    invalid_emails = 0
    emails_by_provider = {}
    original_rows = []
    headers = None
    
    # Debug information
    print(f"\nAnalyzing file: {file_path}")
    print(f"File exists: {os.path.exists(file_path)}")
    
    if not os.path.exists(file_path):
        print(f"ERROR: File '{file_path}' not found. Please check the path and try again.")
        sys.exit(1)
    
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csv_file:
            # Try to detect the dialect
            print("Reading file and detecting CSV format...")
            sample = csv_file.read(1024)
            csv_file.seek(0)
            
            if len(sample.strip()) == 0:
                print("WARNING: The file appears to be empty.")
            
            try:
                # Debug: Show the first part of the file content
                print(f"File sample content (first 100 chars): {repr(sample[:100])}")
                
                sniffer = csv.Sniffer()
                try:
                    dialect = sniffer.sniff(sample)
                    has_header = sniffer.has_header(sample)
                    
                    print(f"Detected CSV dialect: delimiter='{dialect.delimiter}', has_header={has_header}")
                    
                    if has_header:
                        reader = csv.reader(csv_file, dialect=dialect)
                        headers = next(reader)
                        print(f"Headers detected: {headers}")
                        
                        # Store original headers
                        email_col_index = -1
                        
                        # Try to find the email column
                        for i, header in enumerate(headers):
                            if header.lower() == 'email':
                                email_col_index = i
                                break
                        
                        print(f"Email column index: {email_col_index}")
                        
                        # Process rows
                        row_count = 0
                        for row in reader:
                            row_count += 1
                            original_rows.append(row)
                            
                            if email_col_index >= 0 and email_col_index < len(row):
                                email = row[email_col_index].strip()
                                if process_email(email, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns):
                                    valid_emails += 1
                                elif '@' in email:
                                    invalid_emails += 1
                        
                        print(f"Processed {row_count} rows")
                    else:
                        print("No headers detected. Scanning all fields for emails.")
                        reader = csv.reader(csv_file, dialect=dialect)
                        row_count = 0
                        for row in reader:
                            row_count += 1
                            original_rows.append(row)
                            # Try to find email in any column
                            for field in row:
                                if process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns):
                                    valid_emails += 1
                        
                        print(f"Processed {row_count} rows")
                except csv.Error as e:
                    print(f"CSV sniffing error: {e}")
                    # Fall back to the provided delimiter if sniffing fails
                    csv_file.seek(0)
                    print(f"Falling back to default delimiter: '{delimiter}'")
                    reader = csv.reader(csv_file, delimiter=delimiter)
                    
                    # Check first row to see if it looks like a header
                    first_row = next(reader, None)
                    if first_row:
                        print(f"First row: {first_row}")
                        # Check if any field in the first row contains 'email' (case insensitive)
                        if any('email' in field.lower() for field in first_row):
                            headers = first_row
                            print(f"Headers based on first row: {headers}")
                            # Find email column index
                            email_col_index = -1
                            for i, header in enumerate(headers):
                                if 'email' in header.lower():
                                    email_col_index = i
                                    break
                            
                            print(f"Email column index: {email_col_index}")
                        else:
                            # Treat first row as data
                            print("First row doesn't look like headers. Processing as data.")
                            original_rows.append(first_row)
                            for field in first_row:
                                if process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns):
                                    valid_emails += 1
                    
                    # Process remaining rows
                    row_count = 0
                    for row in reader:
                        row_count += 1
                        original_rows.append(row)
                        if headers and email_col_index >= 0 and email_col_index < len(row):
                            email = row[email_col_index].strip()
                            if process_email(email, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns):
                                valid_emails += 1
                            elif '@' in email:
                                invalid_emails += 1
                        else:
                            for field in row:
                                if process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns):
                                    valid_emails += 1
                    
                    print(f"Processed {row_count} rows")
            except Exception as e:
                print(f"Error processing CSV: {e}")
                traceback.print_exc()
                sys.exit(1)
    
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when accessing '{file_path}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        traceback.print_exc()
        sys.exit(1)
        
    return provider_counter, valid_emails, invalid_emails, emails_by_provider, original_rows, headers

def process_email(email, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns=True):
    """Process a single email address."""
    if is_valid_email(email):
        domain = email.split('@')[1].lower()
        provider = get_provider_from_domain(domain)
        
        # If the provider is "Other" and DNS lookups are enabled, try MX records
        if provider == 'Other' and use_dns and DNS_AVAILABLE:
            mx_provider = get_provider_from_mx_records(domain)
            if mx_provider:
                provider = mx_provider
        
        # Increment provider count
        provider_counter[provider] += 1
        
        # Store email by provider
        if provider not in emails_by_provider:
            emails_by_provider[provider] = []
        emails_by_provider[provider].append(email)
        
        return True
    elif '@' in email:
        # Probably a malformed email
        return False
    
    return False

def process_field(field, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns=True):
    """Process a single field to check if it's an email address."""
    # Clean the field
    email = str(field).strip().strip('"\'')
    return process_email(email, provider_counter, emails_by_provider, valid_emails, invalid_emails, use_dns)

def get_default_output_path(input_file):
    """Generate a default output file path based on the input file."""
    base, ext = os.path.splitext(input_file)
    return f"{base}_analysis{ext}"

def print_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, verbose=False):
    """Print analysis results to console."""
    print("\nEMAIL PROVIDER ANALYSIS")
    print("=" * 30)
    
    # Add clear indication if DNS lookups were used
    if DNS_AVAILABLE:
        print("DNS MX lookups: Enabled")
    else:
        print("DNS MX lookups: Disabled (install dnspython for better provider detection)")
    
    print(f"Valid emails: {valid_emails}")
    print(f"Invalid emails: {invalid_emails}")
    print(f"Total: {valid_emails + invalid_emails}")
    
    if valid_emails > 0:
        print("\nProvider Breakdown:")
        print("-" * 30)
        
        # Get sorted providers by count (descending)
        sorted_providers = provider_counter.most_common()
        
        # Calculate column widths for neat formatting
        provider_width = max(len("Provider"), max(len(p) for p, _ in sorted_providers) if sorted_providers else 0)
        count_width = max(len("Count"), len(str(max(c for _, c in sorted_providers) if sorted_providers else 0)))
        
        # Print header with formatting
        print(f"{'Provider':<{provider_width}} | {'Count':>{count_width}} | Percentage")
        print("-" * provider_width + "-+-" + "-" * count_width + "-+-" + "-" * 10)
        
        # Print provider statistics
        for provider, count in sorted_providers:
            percentage = (count / valid_emails) * 100
            # Add stars for providers determined by MX records
            provider_display = provider
            print(f"{provider_display:<{provider_width}} | {count:>{count_width}} | {percentage:.2f}%")
        
        # Print individual emails if verbose mode is enabled
        if verbose:
            print("\nEmails by Provider:")
            print("-" * 30)
            
            for provider, emails in emails_by_provider.items():
                print(f"\n{provider} ({len(emails)}):")
                for email in emails:
                    print(f"  {email}")
    else:
        print("\nNo valid emails found in the file.")

def export_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, original_rows, headers, output_file):
    """Export analysis results to a CSV file, preserving the original format."""
    total_emails = valid_emails + invalid_emails
    
    try:
        print(f"\nExporting results to {output_file}")
        
        # Create a separate summary file
        summary_file = output_file.replace('.csv', '_summary.csv')
        print(f"Creating summary file: {summary_file}")
        
        with open(summary_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write summary section
            writer.writerow(['EMAIL PROVIDER ANALYSIS SUMMARY'])
            writer.writerow(['Total emails', total_emails])
            writer.writerow(['Valid emails', valid_emails])
            writer.writerow(['Invalid emails', invalid_emails])
            
            # Add DNS availability information
            if DNS_AVAILABLE:
                writer.writerow(['DNS MX lookups', 'Enabled'])
            else:
                writer.writerow(['DNS MX lookups', 'Disabled (install dnspython for better provider detection)'])
            
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
        
        # Now create the main output file with the original format
        print(f"Creating main output file: {output_file}")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # First determine if we need to add a provider column
            provider_col_index = -1
            email_col_index = -1
            
            if headers:
                print(f"Using headers: {headers}")
                # Check if we need to add Email Provider column
                for i, header in enumerate(headers):
                    header_lower = header.lower()
                    if 'email provider' in header_lower or 'provider' == header_lower:
                        provider_col_index = i
                    if header_lower == 'email':
                        email_col_index = i
                
                # Write headers, adding Email Provider if needed
                output_headers = list(headers)  # Make a copy to avoid modifying the original
                if provider_col_index == -1:
                    output_headers.append('Email Provider')
                
                writer.writerow(output_headers)
                
                # Process rows
                for row in original_rows:
                    output_row = list(row)  # Make a copy
                    
                    # Find email and determine provider
                    email = None
                    provider = None
                    
                    if email_col_index >= 0 and email_col_index < len(row):
                        email = row[email_col_index].strip()
                        if is_valid_email(email):
                            domain = email.split('@')[1].lower()
                            provider = get_provider_from_domain(domain)
                            
                            # If the provider is "Other" and DNS is available, try MX records
                            if provider == 'Other' and DNS_AVAILABLE:
                                mx_provider = get_provider_from_mx_records(domain)
                                if mx_provider:
                                    provider = mx_provider
                    
                    # Add or update provider info
                    if provider_col_index >= 0 and provider_col_index < len(output_row):
                        if provider:
                            output_row[provider_col_index] = provider
                    else:
                        if provider:
                            output_row.append(provider)
                        else:
                            output_row.append('')
                    
                    writer.writerow(output_row)
            else:
                print("No headers detected. Adding provider as a new column.")
                # If no headers, just write the original rows as is, with provider info as an additional column
                for row in original_rows:
                    output_row = list(row)  # Make a copy
                    
                    # Try to find an email in the row
                    email = None
                    provider = None
                    
                    for field in row:
                        field_str = str(field).strip()
                        if is_valid_email(field_str):
                            email = field_str
                            domain = email.split('@')[1].lower()
                            provider = get_provider_from_domain(domain)
                            
                            # If the provider is "Other" and DNS is available, try MX records
                            if provider == 'Other' and DNS_AVAILABLE:
                                mx_provider = get_provider_from_mx_records(domain)
                                if mx_provider:
                                    provider = mx_provider
                            break
                    
                    # Add provider info
                    if provider:
                        output_row.append(provider)
                    else:
                        output_row.append('')
                    
                    writer.writerow(output_row)
        
        print(f"\nResults exported to {output_file}")
        print(f"Analysis summary exported to {summary_file}")
    
    except Exception as e:
        print(f"Error exporting results: {e}")
        traceback.print_exc()

def create_sample_csv(output_file):
    """Create a sample CSV file with email addresses for testing."""
    print(f"Creating sample CSV file: {output_file}")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Email', 'Company'])
        writer.writerow(['John Doe', 'john.doe@gmail.com', 'Example Inc.'])
        writer.writerow(['Jane Smith', 'jane.smith@outlook.com', 'Sample Corp.'])
        writer.writerow(['Bob Johnson', 'bob@protonmail.com', 'Test LLC'])
        writer.writerow(['Alice Brown', 'alice@yahoo.com', 'Demo Co.'])
        writer.writerow(['Charlie Green', 'charlie@customdomain.com', 'Custom Inc.'])
    print(f"Sample CSV created at {output_file}")
    print("You can now run: python email_analyzer.py sample_emails.csv -v")

def main():
    """Main function to parse arguments and run the analysis."""
    print("\nEmail Provider Analyzer")
    print("======================")
    
    parser = argparse.ArgumentParser(description='Analyze email addresses from a CSV file and categorize them by provider.')
    
    parser.add_argument('input_file', help='Path to the CSV file containing email addresses', nargs='?')
    parser.add_argument('-o', '--output-file', help='Path to save the analysis results (default: inputfile_analysis.csv)')
    parser.add_argument('-d', '--delimiter', default=',', help='CSV delimiter character (default: ,)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print full email lists by provider')
    parser.add_argument('--no-dns', action='store_true', help='Disable DNS MX record lookups')
    parser.add_argument('--create-sample', action='store_true', help='Create a sample CSV file for testing')
    
    args = parser.parse_args()
    
    # Check if creating a sample file was requested
    if args.create_sample:
        create_sample_csv('sample_emails.csv')
        return
    
    # Check if input file was provided
    if not args.input_file:
        parser.print_help()
        print("\nError: You must provide an input file.")
        print("Example usage: python email_analyzer.py emails.csv -v")
        print("To create a sample CSV: python email_analyzer.py --create-sample")
        return
    
    # Display DNS availability information
    if DNS_AVAILABLE:
        print("DNS lookup capability: Available (dnspython is installed)")
    else:
        print("Warning: dnspython is not installed. DNS MX record lookups will be disabled.")
        print("To enable DNS lookups, install dnspython with: pip install dnspython")
        print("This feature enhances provider detection for custom domains.")
        args.no_dns = True
    
    # Default output file is input_file_analysis.csv
    output_file = args.output_file or get_default_output_path(args.input_file)
    
    # Analyze the CSV file
    provider_counter, valid_emails, invalid_emails, emails_by_provider, original_rows, headers = analyze_csv(
        args.input_file, 
        delimiter=args.delimiter,
        use_dns=not args.no_dns
    )
    
    # Print the results
    print_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, args.verbose)
    
    # Export the results
    export_results(provider_counter, valid_emails, invalid_emails, emails_by_provider, original_rows, headers, output_file)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Unhandled exception: {e}")
        traceback.print_exc()
        sys.exit(1)
