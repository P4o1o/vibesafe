/**
 * frameworkDetection.ts
 * 
 * Exports categorized lists of common JavaScript package names to help identify 
 * the technologies used in a scanned project.
 */

// Frontend Frameworks & Libraries
export const frontendPackages: string[] = [
  'react', 
  '@angular/core', 
  'vue', 
  'svelte', 
  'next', // Also backend/fullstack, but strongly indicative of frontend presence
  'nuxt', // Also backend/fullstack
  'gatsby', 
  'remix', // Also backend/fullstack 
  'solid-js', 
  'preact',
  '@emotion/react', // Common styling library often with React
  'styled-components', // Common styling library
  'jquery' // Still common in older projects or specific use cases
];

// Backend Frameworks & Libraries
export const backendPackages: string[] = [
  'express', 
  'fastify', 
  'koa', 
  '@hapi/hapi', // Hapi v17+ scoped package
  'hapi', // Older Hapi
  '@nestjs/core', 
  'sails', 
  '@adonisjs/core', 
  'loopback', 
  'polka',
  'restify',
  'connect', // Base middleware framework, often used directly
  'meteor-base', // Meteor framework indicator
  'next' // Added Next.js here as well, since it includes a backend
];

// Authentication & Authorization Libraries
export const authPackages: string[] = [
  'passport', 
  'jsonwebtoken', 
  'bcrypt', 
  'bcryptjs', // Alternative bcrypt implementation
  '@hapi/basic', // Hapi basic auth
  'express-session', 
  'cookie-session', 
  '@fastify/session', 
  '@fastify/jwt',
  'next-auth',
  'node-jose', // JOSE standards (JWT, JWS, JWE)
  'oidc-provider', // OpenID Connect provider
  'keycloak-connect', // Keycloak adapter for Node.js
  'auth0', // Auth0 SDK
  '@clerk/nextjs', // Added Clerk for Next.js
  '@clerk/clerk-js' // Added Clerk core JS library
];

// Common Middleware Packages (excluding auth, cors, file upload listed separately)
export const middlewarePackages: string[] = [
  'helmet', 
  'body-parser', // Very common, though often built-in now
  'morgan', 
  'compression', 
  'express-validator', 
  'cookie-parser', 
  'csurf', // CSRF protection
  'connect-timeout', // Request timeout middleware
  'response-time', // Response time header middleware
  'rate-limiter-flexible', // Rate limiting
  'express-rate-limit', // Rate limiting for Express
  '@fastify/rate-limit', // Rate limiting for Fastify
  '@fastify/helmet', // Helmet for Fastify
  '@fastify/cookie', // Cookie parsing for Fastify
  'pino-http' // Logging middleware (Pino)
];

// HTTP Client Libraries
export const httpClientPackages: string[] = [
  'axios', 
  'node-fetch', 
  'got', 
  'superagent', 
  'request', // Deprecated but still widely used
  'needle',
  'ky', 
  'undici', // Node.js built-in fetch, also available as package
  '@actions/http-client' // For GitHub Actions
];

// CORS Helper Libraries
export const corsPackages: string[] = [
  'cors', // Standard CORS middleware for Express/Connect
  '@fastify/cors', // CORS plugin for Fastify
  '@koa/cors' // CORS middleware for Koa
];

// File Upload Libraries
export const fileUploadPackages: string[] = [
  'multer', 
  'busboy', // Stream-based parser, often used by other libs
  'formidable', 
  'express-fileupload',
  '@fastify/multipart',
  'connect-busboy' // Busboy middleware for Connect
];

// Combine all lists for potential generic checks or easier iteration
export const allKnownPackages: string[] = [
  ...frontendPackages,
  ...backendPackages,
  ...authPackages,
  ...middlewarePackages,
  ...httpClientPackages,
  ...corsPackages,
  ...fileUploadPackages,
];

// Define the new interface for more granular detection results
export interface DetectedTechnologies {
  hasFrontend: boolean;
  hasBackend: boolean;
  isNextJs: boolean; // Specific flag for Next.js
  hasAuth: boolean;
  hasMiddleware: boolean;
  hasHttpClient: boolean;
  hasCors: boolean;
  hasFileUpload: boolean;
  // Potentially add other specific framework flags here in the future if needed
}

// Simple check function (example - can be expanded)
export const detectTechnologies = (dependencies: string[]): DetectedTechnologies => {
  const detected: DetectedTechnologies = {
    hasFrontend: false,
    hasBackend: false,
    isNextJs: false, // Initialize the new flag
    hasAuth: false,
    hasMiddleware: false, // Generic middleware detection
    hasHttpClient: false,
    hasCors: false,
    hasFileUpload: false,
  };

  const depSet = new Set(dependencies); // Keep Set for efficient lookups of other packages

  // Specific check for Next.js
  if (depSet.has('next')) {
    detected.isNextJs = true;
    detected.hasFrontend = true; // Next.js serves a frontend
    detected.hasBackend = true;  // Next.js has a backend component
  }

  // General frontend and backend checks (avoid re-setting if Next.js already set them)
  if (!detected.hasFrontend && frontendPackages.some(pkg => depSet.has(pkg))) detected.hasFrontend = true;
  if (!detected.hasBackend && backendPackages.some(pkg => depSet.has(pkg) && pkg !== 'next')) detected.hasBackend = true; // Avoid double-counting 'next' if logic changes
  
  // Modified Auth Check: Check predefined list OR if any dependency starts with @clerk/
  if (authPackages.some(pkg => depSet.has(pkg)) || dependencies.some(dep => dep.startsWith('@clerk/'))) {
      detected.hasAuth = true;
  }
  
  if (middlewarePackages.some(pkg => depSet.has(pkg))) detected.hasMiddleware = true;
  if (httpClientPackages.some(pkg => depSet.has(pkg))) detected.hasHttpClient = true;
  if (corsPackages.some(pkg => depSet.has(pkg))) detected.hasCors = true;
  if (fileUploadPackages.some(pkg => depSet.has(pkg))) detected.hasFileUpload = true;
    
  return detected;
}; 