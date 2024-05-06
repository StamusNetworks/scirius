import React, { useState } from 'react';

import { Empty, Tabs } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import EventValue from 'ui/components/EventValue';
import { Signature } from 'ui/components/Signature';
import UICard from 'ui/components/UIElements/UICard';
import endpoints from 'ui/config/endpoints';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import useAutorun from 'ui/helpers/useAutorun';
import { api } from 'ui/mobx/api';
import { SignatureTimeline } from 'ui/pages/Signatures/components';
import Filter from 'ui/utils/Filter';

export const SigContent = styled.div`
  & pre {
    white-space: pre-wrap;
    display: block;
    padding: 10px;
    height: 100%;
    font-size: 14px;
    line-height: 1.66667;
    word-break: break-all;
    word-wrap: break-word;
    color: #747276;
    background-color: white;
    border: 1px solid #ccc;
    border-radius: 1px;
    margin-bottom: 0;
  }

  & .highlight {
    height: 100%;
  }

  & .highlight .err {
    border: none;
  }
`;

export const Row = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 0.5rem;
`;

export const ExpandedSignature = ({ rule, Flow, additionalCards }) => {
  const items = [];
  if (rule.versions?.length > 1) {
    rule.versions
      .sort((a, b) => b.version - a.version)
      .forEach((version, i) => {
        items.push({
          key: i,
          label: `Version ${version.version === 0 ? '< 39' : version.version}`,
          children: <Signature rule={version} key={version.id} />,
        });
      });
  }

  const [ips, setIps] = useState({
    sources: [],
    destinations: [],
  });

  useAutorun(async () => {
    const response = await api.get(endpoints.DASHBOARD_PANEL_NO_FILTER.url, {
      fields: 'src_ip,dest_ip',
      qfilter: `alert.signature_id:${rule.sid}`,
      page_size: 10,
    });
    setIps({
      sources: response.data.src_ip,
      destinations: response.data.dest_ip,
    });
  }, [rule]);

  const cards = [
    {
      title: 'Probes',
      data: rule.probes.map(probe => ({
        key: probe.probe,
        doc_count: probe.hits,
      })),
      key: 'probes',
      filter: 'host',
    },
    {
      title: 'Sources',
      data: ips.sources,
      key: 'sources',
      filter: 'src_ip',
    },
    {
      title: 'Destinations',
      data: ips.destinations,
      key: 'destinations',
      filter: 'dest_ip',
    },
    ...additionalCards,
  ];

  return (
    <div style={{ width: 'calc(100vw - 271px)' }}>
      {rule.versions?.length === 1 && <Signature rule={rule.versions[0]} key={rule.versions[0].id} />}
      {rule.versions?.length > 1 && <Tabs defaultActiveKey="1" items={items} />}
      <SignatureTimeline sid={rule.sid} />
      <Row>
        {cards.map(card => (card.key === 'probes' || card.data?.length > 0) && <Card card={card} key={card.key} />)}
        {/* Probes needs to be displayed if empty */}
      </Row>
      {Flow}
    </div>
  );
};

const Card = ({ card }) => (
  <UICard title={<div>{card.title}</div>} headStyle={{ color: COLOR_BRAND_BLUE, textAlign: 'center' }} bodyStyle={{ padding: '8px 10px' }} noPadding>
    {card.data.map(item => (
      <EventValue filter={new Filter(card.filter, item.key)} count={item.doc_count} />
    ))}
    {card.data.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
  </UICard>
);

ExpandedSignature.propTypes = {
  rule: PropTypes.object,
  Flow: PropTypes.func,
  additionalCards: PropTypes.arrayOf(
    PropTypes.shape({
      title: PropTypes.string,
      data: PropTypes.array,
      key: PropTypes.string,
      filter: PropTypes.string,
    }),
  ),
};

Card.propTypes = {
  card: PropTypes.shape({
    title: PropTypes.string,
    data: PropTypes.array,
    key: PropTypes.string,
    filter: PropTypes.string,
  }),
};

export default ExpandedSignature;
