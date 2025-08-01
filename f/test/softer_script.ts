import { main as echo } from '/f/test/festive_script';

export async function main() {
  const echo = await echo("hello")
  return echo
}
