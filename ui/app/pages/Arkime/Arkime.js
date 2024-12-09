const Arkime = () => null;

Arkime.metadata = {
  category: 'OTHER_APPS',
  url: systemSettings => systemSettings.arkime_url,
  access: (_, systemSettings) => systemSettings.use_arkime,
  title: 'Arkime',
};

export default Arkime;
