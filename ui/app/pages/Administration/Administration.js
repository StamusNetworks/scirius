export const Appliances = () => null;
export const Users = () => null;
export const Sources = () => null;
export const Rulesets = () => null;
export const Other = () => null;

Appliances.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/suricata',
  title: 'Suricata',
  access: permissions => !!permissions.includes('rules.configuration_view'),
};

Users.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/accounts',
  access: permissions => !!permissions.includes('rules.configuration_auth'),
};

Sources.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules/source',
  access: permissions => !!permissions.includes('rules.source_view'),
};

Rulesets.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules/ruleset',
  access: permissions => !!permissions.includes('rules.source_view'),
};

Other.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules',
};
