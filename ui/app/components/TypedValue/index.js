import React from 'react';

import { InfoCircleFilled, RobotOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import { Dropdown } from 'antd';
import _ from 'lodash';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import isIP from 'ui/helpers/isIP';
import { useCustomHistory } from 'ui/hooks/useCustomHistory';
import { useStore } from 'ui/mobx/RootStoreProvider';
import Filter from 'ui/utils/Filter';

const Value = styled.a`
  display: block;
  overflow: hidden;
  cursor: pointer;
  white-space: nowrap;
  text-overflow: ellipsis;
`;

const DropdownLabel = styled.div`
  white-space: nowrap;
  max-width: 350px;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const mitreLinks = ['alert.metadata.mitre_tactic_id', 'alert.metadata.mitre_technique_id'];

const TypedValue = ({ filter, additionalLinks, redirect, children }) => {
  const { commonStore } = useStore();
  const history = useCustomHistory();

  let listOfLinks = additionalLinks || [];

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
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValueHostnameVirus',
        label: (
          <a
            href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(filter.value)) ? 'ip-address' : 'domain'}/${filter.value}`}
            target="_blank"
          >
            <InfoCircleFilled /> <span>External info</span>
          </a>
        ),
      }, // Virus Total Link
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
      {
        key: 'typedValueIP2',
        label: (
          <div
            onClick={() => {
              commonStore.addFilter(filter);

              if (redirect) history.push(`/stamus/hunting/dashboards`);
            }}
          >
            <ZoomInOutlined /> <span>Filter on IP: {filter.displayValue}</span>
          </div>
        ),
      }, // Filter on IP: 0.0.0.0
      {
        key: 'typedValueIP3',
        label: (
          <div
            onClick={() => {
              filter.negated = true;
              commonStore.addFilter(filter);
              if (redirect) history.push(`/stamus/hunting/dashboards`);
            }}
          >
            <ZoomOutOutlined /> <span>Negated filter on IP: {filter.displayValue}</span>
          </div>
        ),
      }, // Negated filter on IP: 0.0.0.0
      {
        key: 'typedValueIP4',
        label: (
          <a
            href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(filter.value)) ? 'ip-address' : 'domain'}/${filter.value}`}
            target="_blank"
          >
            <InfoCircleFilled /> <span>External info</span>
          </a>
        ),
      }, // External info
    ];
  }

  if (filter.type === 'PORT') {
    listOfLinks = [
      ...listOfLinks,
      {
        key: 'typedValuePort',
        label: (
          <a href={`https://www.dshield.org/port.html?port=${filter.displayValue}`} target="_blank">
            <div>
              <InfoCircleFilled /> <span>External info</span>
            </div>
          </a>
        ),
      }, // External info
    ];
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
      }, // External info
    ];
  }

  return (
    <Dropdown
      menu={{
        items: [
          {
            type: 'group', // Must have
            label: <DropdownLabel>{filter.label}</DropdownLabel>,
            children: listOfLinks.filter(({ label }) => !_.isEmpty(label)),
          },
        ],
      }}
      trigger={['contextMenu']}
      destroyPopupOnHide // necessary for the tests! makes sure only one +/- magnifier exists at any time
      onClick={() => commonStore.addFilter(filter)}
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
  redirect: PropTypes.bool,
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  children: PropTypes.node,
};

export default TypedValue;
