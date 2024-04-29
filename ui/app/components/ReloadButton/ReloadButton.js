import React from 'react';

import { ReloadOutlined } from '@ant-design/icons';
import PropTypes from 'prop-types';
import { useDispatch } from 'react-redux';

import actions from 'ui/containers/App/actions';
import { useStore } from 'ui/mobx/RootStoreProvider';

import * as Style from './style';

export const ReloadButton = ({ reloadThreats = () => null }) => {
  const { commonStore } = useStore();
  const dispatch = useDispatch();

  return (
    <Style.ReloadButton
      onClick={() => {
        dispatch(actions.doReload());
        commonStore.reload();
        reloadThreats();
      }}
      icon={<ReloadOutlined />}
      type="ghost"
    >
      Reload
    </Style.ReloadButton>
  );
};

ReloadButton.propTypes = {
  reloadThreats: PropTypes.func,
};
