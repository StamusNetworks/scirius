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

// put all the sections where we want to inlclude `virus total links` for ip addresses and domains
const virusTotalLinks = [
  'hostname_info.domain',
  'http.hostname',
  'dns.query.rrname',
  'http.http_refer_info.domain',
  'tls.sni',
  'http.http_refer_info.host',
  'smtp.helo',
  'hostname_info.host',
];

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
                id: value || '',
                value: value || '',
                label: `IP: ${value}`,
                fullString: true,
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
                id: value,
                value: value,
                label: `IP: ${value}`,
                fullString: true,
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

  if (type !== 'ip' && type !== 'port' && type !== 'username') {
    listOfLinks = [...additionalLinks, ...listOfLinks].filter(obj => !_.isEmpty(obj.label));
  }

  return (
    <Dropdown
      menu={{
        items: listOfLinks,
      }}
      trigger={['click']}
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
