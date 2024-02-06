import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Empty, Spin, Table, Tabs } from 'antd';
import { SafetyOutlined, ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import { sections } from 'ui/constants';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import SciriusChart from 'ui/components/SciriusChart';
import EventValue, { Count } from 'ui/components/EventValue';
import { addFilter } from 'ui/containers/HuntApp/stores/global';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import { useStore } from 'ui/mobx/RootStoreProvider';
import 'ui/pygments.css';
import Filter from 'ui/utils/Filter';
import SignatureFlow from 'ui/components/SignatureFlow';

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

const RuleInList = ({ addFilter, rulesets, rules, filterParams, loading }) => {
  const { commonStore } = useStore();
  const columns = [
    {
      title: '',
      render: () => <SafetyOutlined style={{ color: 'grey' }} />,
    },
    {
      title: 'SID',
      dataIndex: 'sid',
      onHeaderCell: () => ({
        'data-test': 'sid',
      }),
    },
    {
      title: 'Message',
      dataIndex: 'message',
      onHeaderCell: () => ({
        'data-test': 'message',
      }),
    },
    {
      title: 'Created',
      dataIndex: 'created',
      onHeaderCell: () => ({
        'data-test': 'created',
      }),
    },
    {
      title: 'Updated',
      dataIndex: 'updated',
      onHeaderCell: () => ({
        'data-test': 'updated',
      }),
    },
    {
      title: 'Category',
      dataIndex: 'category',
      onHeaderCell: () => ({
        'data-test': 'category',
      }),
    },
    {
      title: 'Alerts',
      dataIndex: 'alerts',
      onHeaderCell: () => ({
        'data-test': 'alerts',
      }),
    },
    {
      title: 'Filter',
      dataIndex: 'filter',
      onHeaderCell: () => ({
        'data-test': 'filter',
      }),
      render: (text, rule) => (
        <React.Fragment>
          <ZoomInOutlined
            data-test="zoom-in-magnifier"
            style={{ marginRight: '10px' }}
            onClick={() => {
              commonStore.addFilter(new Filter('alert.signature_id', rule.sid, { negated: false }));
              addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: rule.sid, negated: false });
            }}
          />
          <ZoomOutOutlined
            data-test="zoom-out-magnifier"
            onClick={e => {
              e.stopPropagation();
              commonStore.addFilter(new Filter('alert.signature_id', rule.sid, { negated: true }));
              addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: rule.sid, negated: true });
            }}
          />
        </React.Fragment>
      ),
    },
    {
      title: 'Ctrl',
      dataIndex: 'ctrl',
      onHeaderCell: () => ({
        'data-test': 'ctrl',
      }),
      render: (text, row) => <RuleEditKebab key={`kebab-${row.sid}`} config={{ rule: row.rule }} rulesets={rulesets} />,
    },
  ];

  const dataSource = rules.map(rule => ({
    key: `${rule.sid}-submenu`,
    sid: rule.sid,
    message: rule.msg,
    created: rule.created,
    updated: rule.updated,
    category: rule.category.name,
    alerts: !rule.hits && rule.hits !== 0 ? <Spin size="small" /> : <Count data-test="signature-alerts-count">{rule.hits}</Count>,
    rule, // we need this to access the rule data in the `expandedRowRender` below
  }));

  const renderContents = rule => {
    const items = [];
    if (rule.versions?.length > 1) {
      rule.versions.forEach((version, i) => {
        items.push({
          key: i,
          label: `Version ${version.version === 0 ? '< 39' : version.version}`,
          children: <SigContent dangerouslySetInnerHTML={{ __html: version.content }} key={version.id} />,
        });
      });
    }
    return (
      <div style={{ width: 'calc(100vw - 271px)' }}>
        {rule.versions?.length === 1 && <SigContent dangerouslySetInnerHTML={{ __html: rule.versions[0].content }} key={rule.versions[0].id} />}
        {rule.versions?.length > 1 && <Tabs defaultActiveKey="1" items={items} />}
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
            <EventValue filter={new Filter('host', probe.probe)} count={probe.hits} />
          ))}
          {rule.probes.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
        </UICard>
        <SignatureFlow rule={rule} />
      </div>
    );
  };

  return (
    <Table
      data-test="signatures-table"
      size="small"
      loading={loading}
      dataSource={dataSource}
      columns={columns}
      expandable={{
        columnWidth: 5,
        expandRowByClick: true,
        expandedRowRender: alert => alert.rule.timeline && renderContents(alert.rule),
        rowExpandable: () => true,
      }}
      pagination={false}
      onRow={(r, index) => ({
        'data-test': `table-row-${index}`,
      })}
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
