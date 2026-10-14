/**
 * The lab revokes one of its researchers. Revocation is permanent: the status
 * endpoint serves REVOKED at once, and no command can undo it.
 *
 *   npm run revoke -- <n>
 */
import { ensureAgent, registrationStatus, revokeAgent } from './dnsid-local.ts';
import { researcherDomain } from './researcher.ts';

const n = Number(process.argv[2]);
if (!Number.isInteger(n) || n < 1) {
  console.error('usage: npm run revoke -- <researcher number>');
  process.exit(2);
}

const domain = researcherDomain(n);
// Act as the lab: researchlab.test is the accountable entity for its researchers.
const lab = await ensureAgent('researchlab.test');
console.log(`${domain}: registration ${await registrationStatus(domain, lab)}`);
console.log('revoke:', await revokeAgent(domain, lab));
console.log(`${domain}: registration ${await registrationStatus(domain, lab)}`);
