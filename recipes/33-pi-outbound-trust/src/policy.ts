import type { ClassifierContext } from '@earendil-works/pi-ai';

// User-owned code/configuration, never tool arguments or codemode store values.
export const policy = {
  version: 'personal-outbound/2',
  impersonationThreshold: 0.3,
  paymentEntities: ['merchant.test'], // Exact verified gi match, not a model opinion.
  maxPaymentCents: 5000,
} as const;

export const questions: ClassifierContext['questions'] = {
  names_org: {
    type: 'bool',
    instructions: 'Does agent_name_unicode reference a well-known company, brand or government body?',
    criteria: { true: 'References an organization', false: 'No organization reference' },
  },
  same_org: {
    type: 'bool',
    instructions: 'Is accountable_entity a known official public domain of the organization referenced in agent_name_unicode? A domain containing a brand name is not evidence of official affiliation.',
    criteria: { true: 'Known official domain of that organization', false: 'Not a known official domain' },
  },
  acts_for: {
    type: 'bool',
    instructions: "Does agent_name_unicode present itself as the named organization's own agent or service (for example its payments, refunds or support), rather than an independent user or integration of its product?",
    criteria: { true: "Presents itself as the organization's agent or service", false: 'No such claim, or clearly an independent user or integration' },
  },
};
