import type { ClassifierContext } from '@earendil-works/pi-ai';

// User-owned code/configuration, never tool arguments or codemode store values.
export const policy = {
  version: 'personal-outbound/1',
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
    instructions: 'Is accountable_entity an official domain of the organization referenced in agent_name_unicode?',
    criteria: { true: 'Official domain of that organization', false: 'Not its official domain' },
  },
  acts_for: {
    type: 'bool',
    instructions: 'Does agent_name_unicode claim to act for the named organization, rather than just use its product?',
    criteria: { true: 'Claims to act for it', false: 'No such claim' },
  },
};
