export function processCookie(cookie: string) {
  const result: Record<string, string | boolean> = {};
  const arr = cookie.split(";");
  for (let part of arr) {
    part = part.trim();

    if (part.includes("HttpOnly")) {
      result.HttpOnly = true;
    } else {
      let [key, value] = part.split("=");
      key = key.trim();
      value = value.trim();
      result[key] = value;
    }
  }
  return result;
}
