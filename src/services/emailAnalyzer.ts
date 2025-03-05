
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
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = (event) => {
      try {
        const result = event.target?.result as string;
        const analysis = processCSVContent(result);
        resolve(analysis);
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => {
      reject(new Error('Error reading file'));
    };
    
    reader.readAsText(file);
  });
};

const processCSVContent = (content: string): AnalysisResult => {
  // Parse CSV content
  const lines = content.split(/\r?\n/).filter(line => line.trim() !== '');
  
  // Initialize variables
  const providerCount: Record<string, number> = {};
  const rawData: Record<string, string[]> = {};
  let validEmails = 0;
  let invalidEmails = 0;
  
  // Process each line to find emails
  lines.forEach(line => {
    // Split by common delimiters (comma, semicolon, tab)
    const parts = line.split(/[,;\t]/);
    
    parts.forEach(part => {
      // Clean the part
      const cleanPart = part.trim().replace(/^["']|["']$/g, '');
      
      // Check if it looks like an email
      if (EMAIL_REGEX.test(cleanPart)) {
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
      }
    });
  });
  
  // Create provider data for chart
  const providers = Object.entries(providerCount)
    .map(([name, value]) => ({
      name,
      value,
      color: PROVIDER_COLORS[name] || PROVIDER_COLORS['Other']
    }))
    .sort((a, b) => b.value - a.value);
  
  return {
    providers,
    totalEmails: validEmails + invalidEmails,
    validEmails,
    invalidEmails,
    raw: rawData
  };
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
