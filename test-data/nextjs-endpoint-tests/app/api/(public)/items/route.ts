// Non-sensitive: app/api route with group (App Router)
export async function GET(request: Request) {
  return new Response('Public Items API endpoint (App Router)');
} 