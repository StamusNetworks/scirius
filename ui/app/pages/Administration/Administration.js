export const Appliances = () => null;
export const Users = () => null;
export const Sources = () => null;
export const Monitoring = () => null;
export const Ryod = () => null;
export const Other = () => null;

Appliances.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/appliances',
};

Users.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/accounts',
};

Sources.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/rules/source',
};

Monitoring.metadata = {
  category: 'ADMINISTRATION',
  url: () => '/appliances/monitoring',
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
