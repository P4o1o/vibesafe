// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
 
export default function handler(req, res) {
  // Potentially exposed endpoint (though common for status)
  res.status(200).json({ name: 'VibeSafe Test Status', status: 'OK' });
} 