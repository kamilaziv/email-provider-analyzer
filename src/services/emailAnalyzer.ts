
interface AnalysisResult {
  providers: {
    name: string;
    value: number;
    color: string;
  }[];
  totalEmails: number;
  validEmails: number;
  invalidEmails: number;
  raw: Record<string, string[]>;
  errors?: string[];
}

// Email provider colors
const PROVIDER_COLORS: Record<string, string> = {
  'Gmail': '#DB4437',
  'Google': '#DB4437',
  'Outlook': '#0078D4',
  'Hotmail': '#0078D4',
  'Microsoft': '#0078D4',
  'Yahoo': '#6001D2',
  'Apple': '#A2AAAD',
  'iCloud': '#A2AAAD',
  'Proton': '#6D4AFF',
  'Yandex': '#F24E1E',
  'Mail.ru': '#005FF9',
  'Zoho': '#F88A1D',
  'AOL': '#31459B',
  'GMX': '#55C3F2',
  'Other': '#718096'
};

// Map domains to providers
const DOMAIN_PROVIDER_MAP: Record<string, string> = {
  // Google
  'gmail.com': 'Gmail',
  'googlemail.com': 'Gmail',
  'google.com': 'Google',
  
  // Microsoft
  'outlook.com': 'Outlook',
  'hotmail.com': 'Hotmail',
  'live.com': 'Microsoft',
  'msn.com': 'Microsoft',
  'microsoft.com': 'Microsoft',
  'office365.com': 'Microsoft',
  
  // Yahoo
  'yahoo.com': 'Yahoo',
  'yahoo.co.uk': 'Yahoo',
  'yahoo.co.jp': 'Yahoo',
  'yahoo.fr': 'Yahoo',
  'ymail.com': 'Yahoo',
  
  // Apple
  'icloud.com': 'iCloud',
  'me.com': 'Apple',
  'mac.com': 'Apple',
  'apple.com': 'Apple',
  
  // Proton
  'proton.me': 'Proton',
  'protonmail.com': 'Proton',
  'pm.me': 'Proton',
  
  // Yandex
  'yandex.ru': 'Yandex',
  'yandex.com': 'Yandex',
  
  // Mail.ru
  'mail.ru': 'Mail.ru',
  'inbox.ru': 'Mail.ru',
  'list.ru': 'Mail.ru',
  'bk.ru': 'Mail.ru',
  
  // Zoho
  'zoho.com': 'Zoho',
  'zohomail.com': 'Zoho',
  
  // AOL
  'aol.com': 'AOL',
  'aim.com': 'AOL',
  
  // GMX
  'gmx.com': 'GMX',
  'gmx.net': 'GMX',
  'gmx.de': 'GMX',
};

// Email validation regex
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

export const analyzeEmailsFromCSV = async (file: File): Promise<AnalysisResult> => {
  console.log(`Starting analysis of file: ${file.name} (${file.size} bytes)`);
  
  return new Promise((resolve, reject) => {
    // Validate file type and size first
    if (!file.name.toLowerCase().endsWith('.csv') && file.type !== 'text/csv') {
      console.error(`Invalid file type: ${file.type}. Expected CSV.`);
      reject(new Error('Invalid file format. Please upload a CSV file.'));
      return;
    }
    
    if (file.size > 10 * 1024 * 1024) { // 10MB limit
      console.error(`File too large: ${file.size} bytes.`);
      reject(new Error('File size exceeds 10MB limit. Please upload a smaller file.'));
      return;
    }
    
    const reader = new FileReader();
    
    reader.onload = (event) => {
      try {
        console.log('File read successful, starting processing...');
        const result = event.target?.result as string;
        
        // Quick check for empty file
        if (!result || result.trim() === '') {
          reject(new Error('The uploaded CSV file is empty. Please check the file and try again.'));
          return;
        }
        
        const analysis = processCSVContent(result, file.name);
        console.log(`Analysis complete: Found ${analysis.validEmails} valid emails across ${analysis.providers.length} providers`);
        resolve(analysis);
      } catch (error) {
        console.error('Error during CSV processing:', error);
        reject(error instanceof Error 
          ? error 
          : new Error('An unexpected error occurred while processing the file.'));
      }
    };
    
    reader.onerror = (event) => {
      console.error('FileReader error:', event);
      reject(new Error('Failed to read the file. Please try again or use a different file.'));
    };
    
    reader.readAsText(file);
  });
};

const processCSVContent = (content: string, fileName: string): AnalysisResult => {
  console.log('Processing CSV content...');
  
  // Initialize variables
  const providerCount: Record<string, number> = {};
  const rawData: Record<string, string[]> = {};
  let validEmails = 0;
  let invalidEmails = 0;
  const errorMessages: string[] = [];
  
  try {
    // Check for BOM character and remove if present
    const contentWithoutBOM = content.replace(/^\uFEFF/, '');
    
    // Parse CSV content - handle different line endings
    const lines = contentWithoutBOM.split(/\r?\n/).filter(line => line.trim() !== '');
    console.log(`Found ${lines.length} non-empty lines in CSV`);
    
    if (lines.length === 0) {
      throw new Error('No data found in the CSV file.');
    }
    
    // Detect delimiter by analyzing first few lines
    const possibleDelimiters = [',', ';', '\t', '|'];
    const delimiterCount = possibleDelimiters.map(delimiter => ({
      delimiter,
      count: lines.slice(0, Math.min(5, lines.length)).reduce(
        (sum, line) => sum + (line.split(delimiter).length - 1), 0
      )
    }));
    
    // Select the delimiter with highest occurrence
    const primaryDelimiter = delimiterCount.sort((a, b) => b.count - a.count)[0].delimiter;
    console.log(`Detected primary delimiter: "${primaryDelimiter}"`);
    
    // Try multiple approaches to find emails
    const foundEmails = new Set<string>();
    let foundAnyEmails = false;
    
    // Process each line to find emails
    lines.forEach((line, index) => {
      // Skip empty lines
      if (!line.trim()) return;
      
      try {
        // Split by detected delimiter
        const parts = line.split(primaryDelimiter);
        
        // Search for emails in parts
        let foundEmailInLine = false;
        parts.forEach(part => {
          // Clean the part - remove quotes and extra spaces
          const cleanPart = part.trim().replace(/^["']|["']$/g, '');
          
          if (EMAIL_REGEX.test(cleanPart)) {
            foundEmailInLine = true;
            foundAnyEmails = true;
            
            // Don't count duplicates
            if (foundEmails.has(cleanPart)) return;
            foundEmails.add(cleanPart);
            
            const domain = cleanPart.split('@')[1].toLowerCase();
            const provider = getProviderFromDomain(domain);
            
            // Increment provider count
            providerCount[provider] = (providerCount[provider] || 0) + 1;
            
            // Store raw data
            if (!rawData[provider]) {
              rawData[provider] = [];
            }
            rawData[provider].push(cleanPart);
            
            validEmails++;
          } else if (cleanPart.includes('@')) {
            // Potentially malformed email
            invalidEmails++;
            
            // Log the first few invalid emails for debugging
            if (invalidEmails <= 5) {
              console.log(`Invalid email format at line ${index + 1}: "${cleanPart}"`);
            }
          }
        });
        
        // If no email found in line, try direct regex search
        if (!foundEmailInLine) {
          const emailMatches = line.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
          if (emailMatches) {
            emailMatches.forEach(email => {
              if (EMAIL_REGEX.test(email) && !foundEmails.has(email)) {
                foundEmails.add(email);
                foundAnyEmails = true;
                
                const domain = email.split('@')[1].toLowerCase();
                const provider = getProviderFromDomain(domain);
                
                providerCount[provider] = (providerCount[provider] || 0) + 1;
                
                if (!rawData[provider]) {
                  rawData[provider] = [];
                }
                rawData[provider].push(email);
                
                validEmails++;
              }
            });
          }
        }
      } catch (lineError) {
        console.error(`Error processing line ${index + 1}:`, lineError);
        errorMessages.push(`Error in line ${index + 1}: ${lineError instanceof Error ? lineError.message : 'Unknown error'}`);
      }
    });
    
    if (!foundAnyEmails) {
      console.warn('No valid emails found in the file');
      
      // Sample the first few lines for debugging
      const sampleLines = lines.slice(0, 3).map(line => `"${line}"`).join(', ');
      console.log(`Sample of first few lines: ${sampleLines}`);
      
      errorMessages.push('No valid email addresses found in the file. Please check the file format and try again.');
    }
    
  } catch (error) {
    console.error('CSV parsing error:', error);
    errorMessages.push(`Error parsing CSV: ${error instanceof Error ? error.message : 'Unknown error'}`);
    
    // Still return whatever we were able to parse
  }
  
  // Create provider data for chart
  const providers = Object.entries(providerCount)
    .map(([name, value]) => ({
      name,
      value,
      color: PROVIDER_COLORS[name] || PROVIDER_COLORS['Other']
    }))
    .sort((a, b) => b.value - a.value);
  
  const result: AnalysisResult = {
    providers,
    totalEmails: validEmails + invalidEmails,
    validEmails,
    invalidEmails,
    raw: rawData
  };
  
  // Only add errors if there are any
  if (errorMessages.length > 0) {
    result.errors = errorMessages;
  }
  
  return result;
};

const getProviderFromDomain = (domain: string): string => {
  // Check if domain is directly mapped
  if (DOMAIN_PROVIDER_MAP[domain]) {
    return DOMAIN_PROVIDER_MAP[domain];
  }
  
  // Check for custom domains used by major providers
  // microsoft365, googleworkspace, etc.
  if (domain.includes('outlook') || domain.includes('office') || domain.includes('microsoft')) {
    return 'Microsoft';
  }
  
  if (domain.includes('google')) {
    return 'Google';
  }
  
  if (domain.includes('yahoo')) {
    return 'Yahoo';
  }
  
  if (domain.includes('zoho')) {
    return 'Zoho';
  }
  
  if (domain.includes('yandex')) {
    return 'Yandex';
  }
  
  if (domain.includes('proton') || domain.includes('pm.me')) {
    return 'Proton';
  }
  
  // Return 'Other' for any unrecognized domain
  return 'Other';
};
