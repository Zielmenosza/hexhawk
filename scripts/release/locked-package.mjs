export function lockedPackageChecksum(lockText, name, version) {
  // Parse Git's LF and Windows CRLF checkouts identically; checksum bytes and
  // package identity values themselves are never rewritten or guessed.
  const entries = lockText.replace(/\r\n/g, '\n').split('[[package]]')
    .filter(block => block.includes(`\nname = "${name}"\n`) && block.includes(`\nversion = "${version}"\n`));
  if (entries.length !== 1) throw new Error('Ambiguous locked WebView2 package.');
  const checksum = entries[0].match(/\nchecksum = "([a-f0-9]{64})"/u)?.[1];
  if (!checksum) throw new Error('Locked registry archive checksum is missing.');
  return checksum;
}
