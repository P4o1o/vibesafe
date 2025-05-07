// @ts-nocheck
import type { NextApiRequest, NextApiResponse } from 'next';

// Sensitive: Dynamic pages/api route
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query;
  res.status(200).json({ message: `Status for ID: ${id}` });
} 