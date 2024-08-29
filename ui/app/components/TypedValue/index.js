import React from 'react';

import { InfoCircleFilled, RobotOutlined, UserOutlined, LinkOutlined } from '@ant-design/icons';
import { Dropdown } from 'antd';
import _ from 'lodash';
import PropTypes from 'prop-types';
import { useHistory } from 'react-router-dom';
import styled from 'styled-components';

import typedOptions from 'ui/components/TypedValue/options';
import isIP from 'ui/helpers/isIP';
import { useStore } from 'ui/mobx/RootStoreProvider';
import Filter from 'ui/utils/Filter';

const Value = styled.a`
  display: block;
  overflow: hidden;
  cursor: pointer;
  white-space: nowrap;
  text-overflow: ellipsis;
  text-decoration: underline dashed lightgray;
  text-underline-offset: 2px;
`;

const DropdownLabel = styled.div`
  white-space: nowrap;
  max-width: 350px;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const mitreLinks = ['alert.metadata.mitre_tactic_id', 'alert.metadata.mitre_technique_id'];

const TypedValue = ({ filter, additionalLinks, children, filterOnClick = true }) => {
  const { commonStore } = useStore();
  const history = useHistory();

  let listOfLinks = additionalLinks || [];

  const customLinks = commonStore.linkTemplates
    .filter(l => l.entities?.map(entity => entity.name).includes(filter.type))
    .map(l => ({
      key: `typedValue${l.name}`,
      label: (
        <a href={l.template?.replace('{{ value }}', filter.value)} target="_blank">
          <LinkOutlined /> <span>{l.name}</span>
        </a>
      ),
    }));

  const getRoleLabel = (location, removeFilters = false) => (
    <div
      onClick={() => {
        if (removeFilters) commonStore.clearFilters();
        commonStore.addFilter(filter);
        // Roles redirection must work regardless of the redirect flag
        if (location) history.push(`/stamus/hunting/${location}`);
      }}
    >
      <RobotOutlined /> <span>Filter on Role{location && `, go to ${_.capitalize(location)}`}</span>
    </div>
  );

  if (filter.type === 'HOSTNAME' || filter.type === 'NAME') {
    const type = isIP(filter.value) ? 'ip-address' : 'domain';
    listOfLinks = [...listOfLinks, typedOptions.EXTERNAL_INFO(type, filter.value)];
  }

  if (filter.type === 'USERNAME') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValueUsername',
        label: (
          <div onClick={() => commonStore.addFilter(filter)}>
            <UserOutlined /> <span>Filter on username</span>
          </div>
        ),
      }, // Filter on username
    ];
  }

  if (filter.type === 'ROLE') {
    listOfLinks = [
      {
        key: 'typedValueRole0',
        label: getRoleLabel(),
      }, // Filter on Role
      {
        key: 'typedValueRole1',
        label: getRoleLabel('hosts'),
      }, // Filter on Role, go to Hosts
      {
        key: 'typedValueRole2',
        label: getRoleLabel('dashboards', true),
      }, // Filter on Role, go to Dashboards (remove filters)
      {
        key: 'typedValueRole3',
        label: getRoleLabel('events'),
      }, // Filter on Role, go to Events
    ];
  }

  if (filter.type === 'IP') {
    listOfLinks = [
      ...listOfLinks,
      typedOptions.FILTER_ON_IP(filter.displayValue, () => {
        commonStore.addFilter(filter);
      }),
      typedOptions.NEGATED_FILTER_ON_IP(filter.displayValue, () => {
        filter.negated = true;
        commonStore.addFilter(filter);
      }),
      typedOptions.EXTERNAL_INFO('ip-address', filter.value),
    ];
  }

  if (filter.type === 'PORT') {
    listOfLinks = [...listOfLinks, typedOptions.EXTERNAL_INFO_PORT(filter.displayValue)];
  }

  if (filter.type === 'SHA256') {
    listOfLinks = [...listOfLinks, typedOptions.EXTERNAL_INFO('file', filter.displayValue)];
  }

  // additionalLinks apply to all fields - ip, port, hostname, username
  if (filter.id === mitreLinks[0] || filter.id === mitreLinks[1]) {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'eventValue3',
        label: (
          <a
            href={(function () {
              if (filter.id === mitreLinks[0]) {
                return `https://attack.mitre.org/tactics/${filter.value}`;
              }
              if (!filter.value.includes('.')) {
                return `https://attack.mitre.org/techniques/${filter.value}`;
              }
              return `https://attack.mitre.org/techniques/${filter.value.split('.')[0]}/${filter.value.split('.')[1]}`;
            })()}
            target="_blank"
          >
            <InfoCircleFilled /> <span>External info</span>
          </a>
        ),
      },
    ];
  }

  return (
    <Dropdown
      menu={{
        items: [
          {
            type: 'group', // Must have
            label: <DropdownLabel>{filter.label}</DropdownLabel>,
            children: [...listOfLinks.filter(({ label }) => !_.isEmpty(label)), ...customLinks],
          },
        ],
      }}
      trigger={[!filterOnClick ? 'hover' : 'contextMenu']}
      destroyPopupOnHide // necessary for the tests! makes sure only one +/- magnifier exists at any time
      onClick={() => {
        if (filterOnClick) commonStore.addFilter(filter);
      }}
    >
      {children || (
        <Value title="Right click for more actions" data-test={filter.displayValue}>
          {filter.displayValue}
        </Value>
      )}
    </Dropdown>
  );
};

TypedValue.defaultProps = {
  additionalLinks: [],
};

TypedValue.propTypes = {
  filter: PropTypes.instanceOf(Filter),
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  children: PropTypes.node,
  filterOnClick: PropTypes.bool,
};

export default TypedValue;
