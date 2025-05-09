import { NpmPackageMetadata } from './npmRegistryClient';

export interface HeuristicWarning {
  type: 'PackageAge' | 'DownloadCount' | 'ReadmePresence' | 'LicensePresence' | 'RepositoryPresence'; // Add more as we implement checks
  message: string;
  details?: any; // Additional details specific to the warning
  severity: 'Low' | 'Medium' | 'High'; // Or some other severity scale if preferred
}

const DEFAULT_MAX_PACKAGE_AGE_DAYS = 30;

/**
 * Checks if the package was published recently.
 * @param metadata The package metadata.
 * @param maxAgeDays The maximum age in days to be considered recent (e.g., 30 days).
 * @returns A HeuristicWarning if the package is new, otherwise null.
 */
export function checkPackageAge(
  metadata: NpmPackageMetadata,
  maxAgeDays: number = DEFAULT_MAX_PACKAGE_AGE_DAYS
): HeuristicWarning | null {
  if (!metadata.time?.created) {
    // Cannot determine age if creation time is missing
    // Depending on strictness, this itself could be a minor warning, but for now, we focus on age.
    return null; 
  }

  try {
    const createdDate = new Date(metadata.time.created);
    const currentDate = new Date();
    const ageInMillis = currentDate.getTime() - createdDate.getTime();
    const ageInDays = ageInMillis / (1000 * 60 * 60 * 24);

    if (ageInDays < 0) {
      // This would be odd (created date in the future), could indicate a system clock issue or bad metadata.
      // For now, we won't flag it as 'new' but it's an edge case.
      return null;
    }

    if (ageInDays <= maxAgeDays) {
      return {
        type: 'PackageAge',
        message: `Package "${metadata.name}" was published recently (on ${createdDate.toLocaleDateString()}).`,
        details: {
          publishedDate: metadata.time.created,
          ageInDays: Math.floor(ageInDays),
          thresholdDays: maxAgeDays,
        },
        severity: 'Medium', // New packages are a moderate concern for slopsquatting
      };
    }
  } catch (error) {
    // console.error(`[heuristicChecks] Error parsing date for package age check: ${metadata.name}`, error);
    // If date parsing fails, we can't determine age. Don't create a warning for age itself.
    return null;
  }

  return null;
}

const DEFAULT_MIN_DOWNLOADS_LAST_MONTH = 50; // As per PRD discussion (e.g., < 50)

/**
 * Checks if the package has very low download volume.
 * @param packageName The name of the package (for messaging).
 * @param downloadData The fetched download data for the package.
 * @param minDownloads The minimum download count for the last month to pass the check.
 * @returns A HeuristicWarning if the download count is too low, otherwise null.
 */
export function checkDownloadVolume(
  packageName: string, // Added packageName for clearer warning messages
  downloadData: { downloads: number; error?: string; start?: string; end?: string }, // Simplified for this check
  minDownloads: number = DEFAULT_MIN_DOWNLOADS_LAST_MONTH
): HeuristicWarning | null {
  // If there was an error fetching download data, we might not want to flag it as low popularity,
  // as the data is missing. However, the PRD implies a warning if it's low.
  // If downloadData.error exists, it means fetchPackageDownloads already identified an issue (e.g., 404)
  // and returned downloads: 0. So, a low download count here could be due to package not found or truly low.

  if (downloadData.downloads < minDownloads) {
    let message = `Package "${packageName}" has very low popularity `;
    message += `(only ${downloadData.downloads} downloads in the last period queried).`;
    
    if (downloadData.error) {
        message += ` Note: There was an issue fetching complete download data: ${downloadData.error}`;
    }

    return {
      type: 'DownloadCount',
      message: message,
      details: {
        downloads: downloadData.downloads,
        threshold: minDownloads,
        period: 'last-month', // Assuming we primarily use last-month as per fetchPackageDownloads default
        fetchError: downloadData.error
      },
      severity: 'Medium', // Low downloads are a moderate concern
    };
  }

  return null;
}

const KNOWN_README_PLACEHOLDERS = [
  'no readme data',
  'no readme found',
  'this package does not have a readme',
  'readme not found',
  'missing readme'
];
const MIN_README_LENGTH = 50; // Minimum characters for a README to be considered non-trivial

/**
 * Checks if the package has a non-trivial README.
 * @param metadata The package metadata.
 * @returns A HeuristicWarning if the README is missing or seems trivial, otherwise null.
 */
export function checkReadmePresence(
  metadata: NpmPackageMetadata
): HeuristicWarning | null {
  const readmeContent = metadata.readme;

  if (readmeContent === null || readmeContent === undefined) {
    return {
      type: 'ReadmePresence',
      message: `Package "${metadata.name}" is missing a README file.`,
      details: { reason: 'README field is null or undefined' },
      severity: 'Low', // Missing README is a low to medium concern
    };
  }

  const trimmedReadme = String(readmeContent).trim();

  if (trimmedReadme === '') {
    return {
      type: 'ReadmePresence',
      message: `Package "${metadata.name}" has an empty README.`,
      details: { reason: 'README is an empty string after trimming' },
      severity: 'Low',
    };
  }

  const lowercasedReadme = trimmedReadme.toLowerCase();
  for (const placeholder of KNOWN_README_PLACEHOLDERS) {
    if (lowercasedReadme.includes(placeholder)) {
      return {
        type: 'ReadmePresence',
        message: `Package "${metadata.name}" has a placeholder README (e.g., "${placeholder}").`,
        details: { reason: 'README content matches known placeholder', matchedPlaceholder: placeholder },
        severity: 'Low',
      };
    }
  }

  if (trimmedReadme.length < MIN_README_LENGTH) {
    return {
      type: 'ReadmePresence',
      message: `Package "${metadata.name}" has a very short README (length: ${trimmedReadme.length} chars).`,
      details: {
        reason: 'README content is shorter than minimum threshold',
        length: trimmedReadme.length,
        threshold: MIN_README_LENGTH,
      },
      severity: 'Low',
    };
  }

  return null;
}

/**
 * Checks if the package has a license specified.
 * @param metadata The package metadata.
 * @returns A HeuristicWarning if the license is missing or unspecified, otherwise null.
 */
export function checkLicensePresence(
  metadata: NpmPackageMetadata
): HeuristicWarning | null {
  let licenseInfo: string | { type: string; url?: string } | undefined | null = undefined;
  let foundIn = 'unknown'; // To track where the license was found for details

  const latestVersionTag = metadata['dist-tags']?.latest;
  if (latestVersionTag && metadata.versions?.[latestVersionTag]) {
    licenseInfo = metadata.versions[latestVersionTag].license;
    foundIn = `versions['${latestVersionTag}'].license`;
  }

  // Fallback to top-level license field if not found in latest version data, or if latest version data is incomplete
  // This is less common for complex packages but can exist for simpler ones.
  if (licenseInfo === undefined && metadata.license !== undefined) {
    licenseInfo = metadata.license;
    foundIn = 'metadata.license (top-level)';
  }

  if (licenseInfo === null || licenseInfo === undefined) {
    return {
      type: 'LicensePresence',
      message: `Package "${metadata.name}" does not specify a license.`,
      details: { reason: 'License field is null or undefined', pathChecked: foundIn },
      severity: 'Low', // Missing license can be a concern for legal/reuse, and sometimes for dubious packages
    };
  }

  if (typeof licenseInfo === 'string') {
    if (licenseInfo.trim() === '') {
      return {
        type: 'LicensePresence',
        message: `Package "${metadata.name}" has an empty string for its license type.`,
        details: { reason: 'License string is empty', pathChecked: foundIn, value: licenseInfo },
        severity: 'Low',
      };
    }
    // If it's a non-empty string (e.g., "MIT", "UNLICENSED"), it's considered present for this check.
    // "UNLICENSED" is a valid way to state no license is granted.
  } else if (typeof licenseInfo === 'object') {
    // It's an object, check for a `type` property
    if (!licenseInfo.type || typeof licenseInfo.type !== 'string' || licenseInfo.type.trim() === '') {
      return {
        type: 'LicensePresence',
        message: `Package "${metadata.name}" has a license object without a valid type specified.`,
        details: { reason: 'License object missing or has empty type property', pathChecked: foundIn, value: licenseInfo },
        severity: 'Low',
      };
    }
  } else {
    // Unexpected type for licenseInfo
    return {
        type: 'LicensePresence',
        message: `Package "${metadata.name}" has an unexpected format for its license information.`,
        details: { reason: 'License field is not a string or recognized object', pathChecked: foundIn, value: licenseInfo },
        severity: 'Low',
    };
  }

  return null;
}

/**
 * Checks if the package has a repository or homepage URL specified.
 * @param metadata The package metadata.
 * @returns A HeuristicWarning if neither a repository URL nor a homepage is found, otherwise null.
 */
export function checkRepositoryPresence(
  metadata: NpmPackageMetadata
): HeuristicWarning | null {
  let hasValidRepositoryUrl = false;
  let hasValidHomepageUrl = false;

  // Check repository field
  const repoField = metadata.repository;
  if (repoField) {
    if (typeof repoField === 'string') {
      const trimmedRepoString = repoField.trim().toLowerCase();
      if (trimmedRepoString.startsWith('http')) {
        hasValidRepositoryUrl = true;
      }
    } else if (typeof repoField === 'object' && repoField.url) {
      const repoUrlValue = repoField.url; // This should be a string based on NpmPackageMetadata
      if (typeof repoUrlValue === 'string') {
        const trimmedRepoUrl = repoUrlValue.trim().toLowerCase();
        if (trimmedRepoUrl.startsWith('http')) {
          hasValidRepositoryUrl = true;
        }
      }
    }
  }

  // Check homepage field
  const homepageField = metadata.homepage;
  if (typeof homepageField === 'string') {
    const trimmedHomepage = homepageField.trim().toLowerCase();
    if (trimmedHomepage.startsWith('http')) {
      hasValidHomepageUrl = true;
    }
  }

  if (!hasValidRepositoryUrl && !hasValidHomepageUrl) {
    return {
      type: 'RepositoryPresence',
      message: `Package "${metadata.name}" does not seem to have a valid repository or homepage URL specified.`,
      details: {
        reason: 'Neither repository.url nor homepage provided a valid-looking URL.',
        repositoryField: metadata.repository, 
        homepageField: metadata.homepage,   
      },
      severity: 'Low', 
    };
  }

  return null;
}

// We will add more check functions here:
// - checkReadmePresence
// - checkLicensePresence
// - checkRepositoryPresence 