import React from 'react';
import PropTypes from 'prop-types';

import { Dropdown, message } from 'antd';
import { CopyOutlined, InfoCircleFilled, RobotOutlined, UserOutlined, ZoomInOutlined, ZoomOutOutlined, DesktopOutlined } from '@ant-design/icons';
import _ from 'lodash';
import styled from 'styled-components';
import history from 'ui/utils/history';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';
import isIP from 'ui/helpers/isIP';
import { useStore } from 'ui/mobx/RootStoreProvider';
import Filter from 'ui/utils/Filter';

const Value = styled.a`
  display: block;
  overflow: hidden;
  word-break: break-all;
  max-height: 20px;
  cursor: pointer;
  white-space: nowrap;
  text-overflow: ellipsis;
`;

const mitreLinks = ['alert.metadata.mitre_tactic_id', 'alert.metadata.mitre_technique_id'];

const TypedValue = ({ filter, additionalLinks, redirect, children }) => {
  const { commonStore } = useStore();

  const onClickHandler = (e, filter) => {
    commonStore.addFilter(filter);
  };

  const virusTotalLink = (
    <a
      href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(filter.instance.value)) ? 'ip-address' : 'domain'}/${filter.instance.value}`}
      target="_blank"
    >
      <InfoCircleFilled /> <span>External info</span>
    </a>
  );

  let listOfLinks = [
    {
      key: 'eventValue1',
      label: (
        <div data-test="filter-on-value" onClick={e => onClickHandler(e, filter.instance)}>
          <ZoomInOutlined /> <span>Filter on value</span>
        </div>
      ),
    },
    {
      key: 'eventValue2',
      label: (
        <div data-test="negated-filter-on-value" onClick={e => onClickHandler(e, filter.negate().instance)}>
          <ZoomOutOutlined /> <span>Negated filter on value</span>
        </div>
      ),
    },
    {
      key: 'copyTextToClipboard',
      label: (
        <div
          onClick={e => {
            e.stopPropagation();
            copyTextToClipboard(filter.displayValue);
            message.success({
              duration: 1,
              content: 'Copied!',
            });
          }}
        >
          <CopyOutlined /> <span>Copy text to clipboard</span>
        </div>
      ),
    },
  ];

  const getRoleLabel = (location, removeFilters = false) => (
    <div
      onClick={e => {
        e.stopPropagation();
        if (removeFilters) commonStore.clearFilters();
        commonStore.addFilter(filter);
        if (redirect && location) history.push(`/stamus/hunting/${location}${window.location.search}`);
      }}
    >
      <RobotOutlined /> <span>Filter on Role{location && `, go to ${_.capitalize(location)}`}</span>
    </div>
  );

  if (filter.instance.type === 'ROLE') {
    listOfLinks = [
      {
        key: 'typedValueRole0',
        label: getRoleLabel(),
      },
      {
        key: 'typedValueRole1',
        label: getRoleLabel('hosts'),
      },
      {
        key: 'typedValueRole2',
        label: getRoleLabel('dashboards', true),
      },
      {
        key: 'typedValueRole3',
        label: getRoleLabel('events'),
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (filter.instance.type === 'IP') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueIP2',
        label: (
          <div
            onClick={e => {
              onClickHandler(e, filter.instance);
              if (redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomInOutlined /> <span>Filter on IP: {filter.displayValue}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP3',
        label: (
          <div
            onClick={e => {
              onClickHandler(e, filter.negate().instance);
              if (redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomOutOutlined /> <span>Negated filter on IP: {filter.displayValue}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP4',
        label: virusTotalLink,
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (filter.instance.type === 'PORT') {
    listOfLinks = [
      ...additionalLinks,
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
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (filter.instance.type === 'HOSTNAME') {
    listOfLinks = [
      {
        key: 'typedValueHostname',
        label: (
          <div onClick={e => onClickHandler(e, filter.instance)}>
            <DesktopOutlined /> <span>Filter on Hostname</span>
          </div>
        ),
      },
      {
        key: 'typedValueHostnameNegated',
        label: (
          <div onClick={e => onClickHandler(e, filter.negate().instance)}>
            <DesktopOutlined /> <span>Negated filter on Hostname</span>
          </div>
        ),
      },
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueHostnameVirus',
        label: virusTotalLink,
      },
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (filter.instance.type === 'USERNAME') {
    listOfLinks = [
      ...additionalLinks,
      {
        key: 'typedValueUsername',
        label: (
          <div onClick={e => onClickHandler(e, filter.instance)}>
            <UserOutlined /> <span>Filter on username</span>
          </div>
        ),
      },
      ...listOfLinks,
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (filter.instance.type === 'NETWORK_INFO') {
    listOfLinks = [
      {
        key: 'typedValueNetInfo',
        label: (
          <div onClick={e => onClickHandler(e, filter.instance)}>
            <UserOutlined /> <span>Filter on Net Info</span>
          </div>
        ),
      },
      {
        key: 'typedValueNetInfoNegated',
        label: (
          <div onClick={e => onClickHandler(e, filter.negate().instance)}>
            <UserOutlined /> <span>Negated filter on Net Info</span>
          </div>
        ),
      },
      ...additionalLinks,
      ...listOfLinks,
    ].filter(obj => !_.isEmpty(obj.label));
  }

  // additionalLinks apply to all fields - ip, port, hostname, username
  if (filter.instance.id === mitreLinks[0] || filter.instance.id === mitreLinks[1]) {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'eventValue3',
        label: (
          <a
            href={(function () {
              if (filter.instance.id === mitreLinks[0]) {
                return `https://attack.mitre.org/tactics/${filter.instance.value}`;
              }
              if (!filter.instance.value.includes('.')) {
                return `https://attack.mitre.org/techniques/${filter.instance.value}`;
              }
              return `https://attack.mitre.org/techniques/${filter.instance.value.split('.')[0]}/${filter.instance.value.split('.')[1]}`;
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
            label: filter.instance.label,
            children: listOfLinks,
          },
        ],
      }}
      trigger={['click']}
      destroyPopupOnHide // necessary for the tests! makes sure only one +/- magnifier exists at any time
      onClick={e => e.stopPropagation()}
    >
      {children || <Value data-test={filter.displayValue}>{filter.displayValue}</Value>}
    </Dropdown>
  );
};

TypedValue.defaultProps = {};

TypedValue.propTypes = {
  filter: PropTypes.instanceOf(Filter),
  redirect: PropTypes.bool,
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  children: PropTypes.node,
};

export default TypedValue;
