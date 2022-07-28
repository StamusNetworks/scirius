export const Appliances = () => null;
export const Users = () => null;
export const Sources = () => null;
export const Monitoring = () => null;
export const Ryod = () => null;
export const Other = () => null;

Appliances.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/appliances',
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

Monitoring.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/appliances/monitoring',
  // eslint-disable-next-line camelcase
  access: permissions => !!permissions?.rules?.configuration_view,
};

Ryod.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/appliances/ryod',
  title: 'RYOD',
};

Other.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules',
};
