with open("api.ts", "r") as f:
    content = f.read()

old = '''const API_BASE = "";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });'''

new = '''const API_BASE = "";

// Read the JWT from sessionStorage (same key used by AuthContext)
function getStoredToken(): string | null {
  try { return sessionStorage.getItem("soc_jwt_token"); } catch { return null; }
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getStoredToken();
  const authHeader: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...authHeader, ...options?.headers },
    ...options,
  });'''

if old in content:
    content = content.replace(old, new)
    with open("api.ts", "w") as f:
        f.write(content)
    print("Patched successfully")
else:
    print("OLD string not found")
