import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Dropdown, message } from 'antd';
import { CopyOutlined, IdcardOutlined, InfoCircleFilled, UserOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import _ from 'lodash';
import styled from 'styled-components';
import { Link } from 'ui/helpers/Link';
import history from 'ui/utils/history';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import { sections } from 'ui/constants';
import copyTextToClipboard from 'ui/helpers/copyTextToClipboard';
import isIP from 'ui/helpers/isIP';

const Value = styled.a`
  overflow: hidden;
  text-overflow: ellipsis;
`;

const TypedValue = ({ addFilter, additionalLinks, printedValue, redirect, value, type }) => {
  const virusTotalLink = (
    <a href={`https://www.virustotal.com/gui/${isIP(encodeURIComponent(value)) ? 'ip-address' : 'domain'}/${value}`} target="_blank">
      <InfoCircleFilled /> <span>External info</span>
    </a>
  );

  let listOfLinks = [
    {
      key: 'copyTextToClipboard',
      label: (
        <div
          onClick={e => {
            e.stopPropagation();
            copyTextToClipboard(printedValue || value);
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

  if (type === 'ip') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueIP1',
        label: (
          <Link to={`/stamus/hunting/hosts/host-insight/${value}`}>
            <div>
              <IdcardOutlined /> <span>Open Host Insight page for IP</span>
            </div>
          </Link>
        ),
      },
      {
        key: 'typedValueIP2',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              addFilter(sections.GLOBAL, {
                id: 'ip',
                value: value || '',
                label: `IP: ${value}`,
                fullString: false,
                negated: false,
                query: 'filter',
              });
              if (redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomInOutlined /> <span>Filter on IP: {value}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP3',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              addFilter(sections.GLOBAL, {
                id: 'ip',
                value: value || '',
                label: `IP: ${value}`,
                fullString: false,
                negated: true,
                query: 'filter',
              });
              if (redirect) history.push('/stamus/hunting/dashboards');
            }}
          >
            <ZoomOutOutlined /> <span>Negated filter on IP: {value}</span>
          </div>
        ),
      },
      {
        key: 'typedValueIP4',
        label: virusTotalLink,
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'port') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValuePort',
        label: (
          <a href={`https://www.dshield.org/port.html?port=${value}`} target="_blank">
            <div>
              <InfoCircleFilled /> <span>External info</span>
            </div>
          </a>
        ),
      },
    ].filter(obj => !_.isEmpty(obj.label)); // removes the ones that dont have data;
  }

  if (type === 'hostname') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueHostname',
        label: virusTotalLink,
      },
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type === 'username') {
    listOfLinks = [
      ...additionalLinks,
      ...listOfLinks,
      {
        key: 'typedValueUsername',
        label: (
          <div
            onClick={e => {
              e.stopPropagation();
              addFilter(sections.GLOBAL, {
                id: 'host_id.username.user',
                value: value || '',
                label: `host_id.username.user: ${value}`,
                fullString: false,
                negated: false,
              });
            }}
          >
            <UserOutlined /> <span>Filter on username</span>
          </div>
        ),
      },
    ].filter(obj => !_.isEmpty(obj.label));
  }

  if (type !== 'ip' && type !== 'port' && type !== 'username' && type !== 'hostname') {
    listOfLinks = [...additionalLinks, ...listOfLinks].filter(obj => !_.isEmpty(obj.label));
  }

  return (
    <Dropdown
      menu={{
        items: listOfLinks,
      }}
      trigger={['click']}
      destroyPopupOnHide // necessary for the tests! makes sure only one +/- magnifier exists at any time
      onClick={e => e.stopPropagation()}
    >
      <Value data-test={printedValue || value}>{printedValue || value}</Value>
    </Dropdown>
  );
};

TypedValue.defaultProps = {
  additionalLinks: [],
};

TypedValue.propTypes = {
  type: PropTypes.string.isRequired, // 'ip|hostname|username|port'
  value: PropTypes.string.isRequired,
  redirect: PropTypes.bool,
  additionalLinks: PropTypes.arrayOf(PropTypes.object),
  addFilter: PropTypes.func,
  printedValue: PropTypes.string,
};

export default connect(null, { addFilter })(TypedValue);
