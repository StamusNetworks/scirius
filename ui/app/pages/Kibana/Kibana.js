const Kibana = () => null;

Kibana.metadata = {
  category: 'OTHER_APPS',
  url: systemSettings => systemSettings.kibana_url,
  access: (permissions, systemSettings) => systemSettings.kibana && permissions.includes('rules.events_kibana'),
  computedTitle: systemSettings => (systemSettings.use_opensearch ? 'Dashboards' : 'Kibana'),
};

export default Kibana;
