import React from 'react';

import { SafetyOutlined } from '@ant-design/icons';
import { Spin, Table } from 'antd';
import PropTypes from 'prop-types';

import EventValue, { Count } from 'ui/components/EventValue';
import ExpandedSignature from 'ui/components/ExpandedSignature';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import 'ui/pygments.css';
import Filter from 'ui/utils/Filter';

const RuleInList = ({ rulesets, rules, filterParams, loading }) => {
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
      render: val => <EventValue filter={new Filter('alert.signature_id', val)} />,
    },
    {
      title: 'Message',
      dataIndex: 'message',
      onHeaderCell: () => ({
        'data-test': 'message',
      }),
      render: val => <EventValue filter={new Filter('msg', val)} />,
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
        expandedRowRender: alert => alert.rule.timeline && <ExpandedSignature rule={alert.rule} filterParams={filterParams} />,
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
};

export default RuleInList;
