import fetch from 'node-fetch'; // Using node-fetch for broader Node version compatibility for now

// A more specific interface can be defined as we identify necessary fields
export interface NpmPackageMetadata {
  name: string;
  description?: string;
  versions?: Record<string, any>; // Object with version strings as keys
  time?: {
    created: string;
    modified: string;
    [version: string]: string; // e.g., "1.0.0": "2023-01-01T12:00:00.000Z"
  };
  repository?: {
    type: string;
    url: string;
  } | string; // Allow repository to be a string URL directly
  homepage?: string;
  license?: string | { type: string, url: string };
  readme?: string;
  // Add more fields as needed based on PRD checks
  [key: string]: any; // Allow other properties
}

const NPM_REGISTRY_URL = 'https://registry.npmjs.org';

/**
 * Fetches package metadata from the npm registry.
 * @param packageName The name of the package to fetch.
 * @returns A promise that resolves to the package metadata.
 * @throws Throws an error if the fetch fails or the package is not found.
 */
export async function fetchPackageMetadata(packageName: string): Promise<NpmPackageMetadata> {
  if (!packageName || typeof packageName !== 'string' || packageName.trim() === '') {
    throw new Error('Package name must be a non-empty string.');
  }

  const encodedPackageName = encodeURIComponent(packageName);
  const url = `${NPM_REGISTRY_URL}/${encodedPackageName}`;

  try {
    // console.log(`[npmRegistryClient] Fetching metadata for: ${packageName} from ${url}`);
    const response = await fetch(url);

    if (!response.ok) {
      if (response.status === 404) {
        throw new Error(`Package "${packageName}" not found in npm registry (404).`);
      }
      throw new Error(`Failed to fetch package metadata for "${packageName}". Status: ${response.status} ${response.statusText}`);
    }

    const metadata = await response.json() as NpmPackageMetadata;
    // console.log(`[npmRegistryClient] Successfully fetched metadata for: ${packageName}`);
    return metadata;
  } catch (error: any) {
    // console.error(`[npmRegistryClient] Error fetching metadata for ${packageName}:`, error.message);
    // Re-throw the error to be handled by the caller, ensuring it's an Error instance
    if (error instanceof Error) {
      throw error;
    }
    throw new Error(`An unexpected error occurred while fetching metadata for "${packageName}": ${String(error)}`);
  }
}

export interface NpmDownloadData {
  downloads: number;
  start: string;
  end: string;
  package: string;
  error?: string; // To capture any error messages from the API or our handling
}

const NPM_DOWNLOADS_API_URL = 'https://api.npmjs.org/downloads/point';

/**
 * Fetches package download counts from the npm API for a given period.
 * @param packageName The name of the package.
 * @param period The period for which to fetch downloads (e.g., 'last-month').
 * @returns A promise that resolves to the download data.
 */
export async function fetchPackageDownloads(
  packageName: string,
  period: 'last-day' | 'last-week' | 'last-month' = 'last-month'
): Promise<NpmDownloadData> {
  if (!packageName || typeof packageName !== 'string' || packageName.trim() === '') {
    // Consistent error with fetchPackageMetadata
    throw new Error('Package name must be a non-empty string for fetching downloads.');
  }
  const encodedPackageName = encodeURIComponent(packageName);
  const url = `${NPM_DOWNLOADS_API_URL}/${period}/${encodedPackageName}`;

  try {
    // console.log(`[npmRegistryClient] Fetching downloads for: ${packageName}, period: ${period} from ${url}`);
    const response = await fetch(url);

    if (!response.ok) {
      // For 404, npm downloads API might mean the package truly doesn't exist OR has no download data for the period.
      // It often returns a body like: {"error":"package not found"} or similar for new/obscure packages.
      if (response.status === 404) {
        // Attempt to parse the error message from the API if available
        let errorMessage = `Package or download data for "${packageName}" not found for period "${period}" (404).`;
        try {
            const errorData = await response.json();
            if (errorData && errorData.error) {
                errorMessage = `Error fetching downloads for "${packageName}" (${period}): ${errorData.error} (404).`;
            }
        } catch (e) { /* Ignore parsing error, use default message */ }
        // console.warn(`[npmRegistryClient] ${errorMessage}`);
        // Return a structure indicating 0 downloads but also signaling an issue/missing data clearly.
        return {
          downloads: 0,
          start: '', // Or derive from period if possible, but not critical if error
          end: '',
          package: packageName,
          error: errorMessage
        };
      }
      // For other errors, throw a more generic error
      throw new Error(`Failed to fetch downloads for "${packageName}". Status: ${response.status} ${response.statusText}`);
    }

    const downloadData = await response.json() as NpmDownloadData;
    // console.log(`[npmRegistryClient] Successfully fetched downloads for: ${packageName}`);
    return downloadData;
  } catch (error: any) {
    // console.error(`[npmRegistryClient] Error fetching downloads for ${packageName}:`, error.message);
    if (error instanceof Error) {
        // If it's one of our custom errors (like the 404 above that we reformat), just rethrow
        // Otherwise, wrap it for consistency
        if (error.message.includes('Package name must be a non-empty string')) throw error;
        throw new Error(`An unexpected error occurred while fetching downloads for "${packageName}": ${error.message}`);
    }
    throw new Error(`An unexpected error occurred while fetching downloads for "${packageName}": ${String(error)}`);
  }
}

// Example of how to fetch download counts (will be a separate function later as per PRD)
// const NPM_DOWNLOADS_API_URL = 'https://api.npmjs.org/downloads/point';
// export async function fetchPackageDownloads(packageName: string, period: 'last-day' | 'last-week' | 'last-month' = 'last-month'): Promise<any> {
//   const url = `${NPM_DOWNLOADS_API_URL}/${period}/${packageName}`;
//   try {
//     const response = await fetch(url);
//     if (!response.ok) {
//       if (response.status === 404) { // Sometimes 404 means no download data or package doesn't exist
//         // console.warn(`[npmRegistryClient] No download data found for "${packageName}" for period "${period}" (404).`);
//         return { downloads: 0, package: packageName }; // Return 0 downloads
//       }
//       throw new Error(`Failed to fetch downloads for "${packageName}". Status: ${response.status}`);
//     }
//     return await response.json();
//   } catch (error) {
//     // console.error(`[npmRegistryClient] Error fetching downloads for ${packageName}:`, error);
//     throw error; // Re-throw to be handled by caller
//   }
// } 