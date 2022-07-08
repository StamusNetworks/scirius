const Kibana = () => null;

Kibana.metadata = {
  category: 'OTHER_APPS',
  url: systemSettings => systemSettings.kibana_url,
  access: (permissions, systemSettings) => systemSettings.kibana && permissions.includes('rules.events_kibana'),
};

export default Kibana;
