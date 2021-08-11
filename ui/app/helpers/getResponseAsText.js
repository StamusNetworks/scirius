export async function getResponseAsText(response) {
  const text = await response.text().then(t => t);
  return text;
}
