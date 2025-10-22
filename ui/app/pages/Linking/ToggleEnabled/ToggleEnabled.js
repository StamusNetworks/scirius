import React from 'react';

import { Switch } from 'antd';
import PropTypes from 'prop-types';

import API from 'ui/services/API';

export const ToggleEnabled = ({ pk, onSuccess, enabled }) => {
  const handleToggleEnabled = async () => {
    await API.updateDeeplink(pk, { body: { enabled: !enabled } });
    onSuccess();
  };
  return <Switch checked={enabled} onChange={handleToggleEnabled} />;
};

ToggleEnabled.propTypes = {
  pk: PropTypes.number.isRequired,
  onSuccess: PropTypes.func.isRequired,
  enabled: PropTypes.bool.isRequired,
};
