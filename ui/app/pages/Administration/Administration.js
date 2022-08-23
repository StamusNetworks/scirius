export const Appliances = () => null;
export const Users = () => null;
export const Sources = () => null;
export const Other = () => null;

Appliances.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/suricata',
  title: 'Suricata',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions.indexOf('rules.configuration_view') !== -1,
};

Users.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/accounts',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions.indexOf('rules.configuration_auth') !== -1,
};

Sources.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules/source',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions.indexOf('rules.source_view') !== -1,
};

Other.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules',
};
