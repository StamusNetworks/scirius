const EveBox = () => null;

EveBox.metadata = {
  category: 'OTHER_APPS',
  url: (systemSettings) => systemSettings.evebox_url,
  access: (permissions, systemSettings) => systemSettings.evebox && permissions.includes('rules.events_evebox'),
}

export default EveBox;
