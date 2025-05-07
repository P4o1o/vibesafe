// Sensitive: Dynamic app/api route (App Router)
export async function GET(request: Request, { params }: { params: { slug: string } }) {
  return new Response(`Info for slug: ${params.slug} (App Router)`);
} 