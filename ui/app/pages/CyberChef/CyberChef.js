const CyberChef = () => null;

CyberChef.metadata = {
  category: 'OTHER_APPS',
  url: systemSettings => systemSettings.cyberchef_url,
  access: (permissions, systemSettings) => systemSettings.cyberchef,
  title: 'CyberChef',
};

export default CyberChef;
