import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Spin, Table } from 'antd';
import { ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import { sections } from 'ui/constants';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import SciriusChart from 'ui/components/SciriusChart';
import EventValue from 'ui/components/EventValue';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';

export const SigContent = styled.div`
  & pre {
    white-space: pre-wrap;
    display: block;
    padding: 10px;
    height: 100%;
    font-size: 11px;
    line-height: 1.66667;
    word-break: break-all;
    word-wrap: break-word;
    color: #747276;
    background-color: #fafafa;
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

const RuleInList = ({ addFilter, rulesets, rules, filterParams, loading }) => {
  const [expand, setExpand] = useState(true);

  const columns = [
    {
      title: 'SID',
      dataIndex: 'sid',
    },
    {
      title: 'Message',
      dataIndex: 'message',
    },
    {
      title: 'Created',
      dataIndex: 'created',
    },
    {
      title: 'Updated',
      dataIndex: 'updated',
    },
    {
      title: 'Category',
      dataIndex: 'category',
    },
    {
      title: 'Alerts',
      dataIndex: 'alerts',
    },
    {
      title: 'Filter',
      dataIndex: 'filter',
      render: (text, rule) => (
        <React.Fragment>
          <ZoomInOutlined
            style={{ marginRight: '10px' }}
            onClick={() => addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: rule.sid, negated: false })}
          />
          <ZoomOutOutlined
            onClick={e => {
              e.stopPropagation();
              addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: rule.sid, negated: true });
            }}
          />
        </React.Fragment>
      ),
    },
    {
      title: 'Ctrl',
      dataIndex: 'ctrl',
      render: (text, rule) => <RuleEditKebab key={`kebab-${rule.sid}`} config={{ rule }} rulesets={rulesets} setExpand={setExpand} />,
    },
  ];

  const dataSource = rules.map(rule => ({
    key: `${rule.sid}-submenu`,
    sid: rule.sid,
    message: rule.msg,
    created: rule.created,
    updated: rule.updated,
    category: rule.category.name,
    alerts: !rule.hits && rule.hits !== 0 ? <Spin size="small" /> : rule.hits,
    rule, // we need this to access the rule data in the `expandedRowRender` below
  }));

  const renderContents = rule => (
    <div style={{ height: '100%', width: 'calc(100vw - 260px)' }}>
      {/* eslint-disable-next-line react/no-danger */}
      <SigContent dangerouslySetInnerHTML={{ __html: rule.content }} />
      <SciriusChart
        data={rule.timeline}
        axis={{ x: { min: filterParams.fromDate, max: filterParams.toDate } }}
        legend={{ show: false }}
        padding={{ bottom: 10 }}
      />
      <UICard
        title={<div>Probes</div>}
        style={{ width: '300px' }}
        headStyle={{ color: COLOR_BRAND_BLUE, textAlign: 'center' }}
        bodyStyle={{ padding: '8px 10px' }}
        noPadding
      >
        {rule.probes.map(probe => (
          <EventValue field="host" value={probe.probe} right_info={probe.hits} />
        ))}
      </UICard>
    </div>
  );

  return (
    <Table
      style={{ marginTop: '10px', marginBottom: '10px' }}
      size="small"
      loading={loading}
      dataSource={dataSource}
      columns={columns}
      expandable={{
        columnWidth: 5,
        expandRowByClick: expand,
        expandedRowRender: alert => alert.rule.timeline && renderContents(alert.rule),
        rowExpandable: () => true,
      }}
      pagination={false}
    />
  );
};

RuleInList.propTypes = {
  loading: PropTypes.bool,
  rules: PropTypes.any,
  rulesets: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  addFilter: PropTypes.any,
};

const mapDispatchToProps = {
  addFilter,
};

export default connect(null, mapDispatchToProps)(RuleInList);
