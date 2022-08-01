export const Appliances = () => null;
export const Users = () => null;
export const Sources = () => null;
export const Other = () => null;

Appliances.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/suricata',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions?.rules?.configuration_view,
};

Users.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/accounts',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions?.rules?.configuration_auth,
};

Sources.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules/source',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions?.rules?.source_view,
};

Other.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules',
};
