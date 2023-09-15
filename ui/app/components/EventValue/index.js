import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { InfoCircleFilled, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import TypedValue from 'ui/components/TypedValue';
import styled from 'styled-components';
import { COLOR_BOX_HEADER } from 'ui/constants/colors';
import IP_FIELDS from 'ui/config/ipFields';
import { useStore } from 'ui/mobx/RootStoreProvider';

const mitreLinks = [
  'alert.metadata.mitre_tactic_id',
  'alert.metadata.mitre_technique_id',
  'alert.metadata.mitre_tactic_name',
  'alert.metadata.mitre_technique_name',
];

const Container = styled.div`
  display: grid;
  grid-template-columns: 1fr min-content;
  align-items: center;
  width: 100%;
  background: ${p => (p.hover ? '#f0f2f5' : 'none')};
  cursor: pointer;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

export const Count = styled.span`
  background: ${COLOR_BOX_HEADER};
  color: #fff;
  padding: 0 5px;
  font-size: 12px;
`;

const EventValue = ({ copyMode, field, format, right_info: rightInfo, value }) => {
  const { commonStore } = useStore();

  const printValue = () => {
    if (!mitreLinks.includes(field)) {
      if (format) return format(value);
      return value;
    }
    if (!value.toString().includes('_')) return value;

    return value.toString().replaceAll('_', ' ');
  };

  const [hover, setHover] = useState(false);

  let type;
  // additionalLinks apply to all fields - ip, port, hostname, username
  let additionalLinks = [
    {
      key: 'eventValue1',
      label: (
        <div
          onClick={() => {
            commonStore.addFilter({
              id: field || '',
              value: value || '',
              label: `${field}: ${format ? format(value) : value}`,
              fullString: true,
              negated: false,
            });
          }}
        >
          <ZoomInOutlined /> <span data-test="filter-on-value">Filter on value</span>
        </div>
      ),
    },
    {
      key: 'eventValue2',
      label: (
        <div
          onClick={() => {
            commonStore.addFilter({
              id: field,
              value: value || '',
              label: `${field}: ${format ? format(value) : value}`,
              fullString: true,
              negated: true,
            });
          }}
        >
          <ZoomOutOutlined /> <span data-test="negated-filter-on-value">Negated filter on value</span>
        </div>
      ),
    },
  ];

  if (field === mitreLinks[0] || field === mitreLinks[1]) {
    additionalLinks = [
      ...additionalLinks,
      {
        key: 'eventValue3',
        label: (field === mitreLinks[0] || field === mitreLinks[1]) && (
          <a
            href={(function () {
              if (field === mitreLinks[0]) {
                return `https://attack.mitre.org/tactics/${value}`;
              }
              if (!value.includes('.')) {
                return `https://attack.mitre.org/techniques/${value}`;
              }
              return `https://attack.mitre.org/techniques/${value.split('.')[0]}/${value.split('.')[1]}`;
            })()}
            target="_blank"
          >
            <InfoCircleFilled /> <span>External info</span>
          </a>
        ),
      },
    ];
  }

  // IP
  if (IP_FIELDS.includes(field)) {
    type = 'ip';
  }

  // PORT
  if (['src_port', 'dest_port', 'host_id.services.port'].includes(field)) {
    type = 'port';
  }

  // HOSTNAME
  if (
    [
      'hostname_info.domain',
      'http.hostname',
      'dns.query.rrname',
      'http.http_refer_info.domain',
      'tls.sni',
      'http.http_refer_info.host',
      'smtp.helo',
      'hostname_info.host',
    ].includes(field)
  ) {
    type = 'hostname';
  }

  // USERNAME
  if (['smtp.mail_from', 'smtp.rcpt_to'].includes(field)) {
    type = 'username';
  }

  return (
    <Container data-test="event-value" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)} hover={hover}>
      <TypedValue type={type} value={value} additionalLinks={additionalLinks} printedValue={printValue()} />
      {rightInfo && !(copyMode && hover) && <Count>{rightInfo}</Count>}
    </Container>
  );
};

EventValue.propTypes = {
  right_info: PropTypes.any,
  field: PropTypes.any,
  value: PropTypes.any,
  format: PropTypes.func,
  copyMode: PropTypes.bool,
};

export default EventValue;
