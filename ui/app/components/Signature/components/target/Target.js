import React from 'react';

import { Tooltip } from 'antd';
import PropTypes from 'prop-types';

import { TargetIcon, ServerIcon, ClientIcon, ArrowIcon } from 'ui/assets/icons';

import * as Signature from '../../styles';
import * as Styled from './styles';

export const Target = ({ destination, target }) => {
  if (destination === 'unknown') return null;
  const start = destination === 'client' ? server : client;
  const end = destination === 'client' ? client : server;
  return (
    <Signature.Field>
      <Styled.Row>
        <Styled.Cell>
          {start.icon}
          {start.label}
          {target === 'source' && (
            <Tooltip title={`${start.label} is the target`}>
              <Styled.Target>
                <TargetIcon />
              </Styled.Target>
            </Tooltip>
          )}
        </Styled.Cell>
        <Styled.Cell>
          <ArrowIcon />
        </Styled.Cell>
        <Styled.Cell>
          {end.icon}
          {end.label}
          {target === 'destination' && (
            <Tooltip title={`${end.label} is the target`}>
              <Styled.Target>
                <TargetIcon />
              </Styled.Target>
            </Tooltip>
          )}
        </Styled.Cell>
      </Styled.Row>
    </Signature.Field>
  );
};

Target.propTypes = {
  destination: PropTypes.string.isRequired,
  target: PropTypes.string.isRequired,
};

const client = {
  label: 'Client',
  icon: ClientIcon,
};
const server = {
  label: 'Server',
  icon: ServerIcon,
};
