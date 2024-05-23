/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-gnetworks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/

import React, { useState, useEffect } from 'react';

import { Table } from 'antd';
import { Helmet } from 'react-helmet';

import FilterEditKebab from 'ui/components/FilterEditKebab';
import { STAMUS } from 'ui/config';
import notify from 'ui/helpers/notify';
import API from 'ui/services/API';

import ActionItem from './ActionItem';
import * as Style from './style';

const PoliciesPage = () => {
  const [data, setData] = useState([]);
  const [count, setCount] = useState(0);
  const [rulesets, setRulesets] = useState({});
  const [expand, setExpand] = useState(true);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({ current: 1, pageSize: 10 });

  const fetchRulesets = async () => {
    try {
      const res = await API.fetchRuleSets();
      const newRulesets = {};
      res.data.results.forEach(result => {
        newRulesets[result.pk] = result;
      });
      setRulesets(newRulesets);
    } catch {
      notify('Failed to fetch rulesets');
    }
  };

  useEffect(() => {
    if (Object.keys(rulesets).length === 0) {
      fetchRulesets();
    }
  }, [rulesets]);

  useEffect(() => {
    fetchData();
  }, [pagination]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await API.fetchProcessingFilters({
        page: pagination.current,
        page_size: pagination.pageSize,
        ordering: '-timestamp',
      });
      setData(res.data.results);
      setCount(res.data.count);
    } catch {
      notify('Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  const handleTableChange = (page, pageSize) => {
    setPagination({
      current: page,
      pageSize,
    });
  };

  const getRowRuleSets = item => item.rulesets.map(rsId => <Style.DescriptionItem key={rsId}>{rulesets[rsId]?.name}</Style.DescriptionItem>);

  const getRowDescription = item => {
    let description = [];
    if (item.action === 'threshold') {
      description.push(
        <Style.DescriptionItem key="track">
          <strong>track</strong>: {item.options.track}
        </Style.DescriptionItem>,
      );
    } else if (item.action === 'threat') {
      description.push(
        <Style.DescriptionItem key="threat">
          <strong>threat</strong>: {item.options.threat}
        </Style.DescriptionItem>,
      );
    } else if (item.action !== 'suppress') {
      description = Object.keys(item.options).map(option => (
        <Style.DescriptionItem key={option}>
          <strong>{option}</strong>: {item.options[option]}
        </Style.DescriptionItem>
      ));
    }
    return description;
  };

  const getRowFilters = (item, size) => {
    const filters = [];

    if (item.filter_defs.length === 0) {
      return [];
    }
    const limit = size || item.filter_defs.length;
    for (let i = 0; i < limit; i += 1) {
      let info = (
        <Style.DescriptionItem key={i}>
          {item.filter_defs[i].operator === 'different' && 'Not '}
          <strong>{item.filter_defs[i].key}</strong>: {item.filter_defs[i].value}
        </Style.DescriptionItem>
      );
      if (item.filter_defs[i].key === 'alert.signature_id' && item.filter_defs[i].msg) {
        info = (
          <Style.DescriptionItem key={i}>
            {item.filter_defs[i].operator === 'different' && 'Not '}
            <strong>{item.filter_defs[i].key}</strong>: {item.filter_defs[i].value} ({item.filter_defs[i].msg})
          </Style.DescriptionItem>
        );
      }
      filters.push(info);
    }
    if (size && size < item.filter_defs.length) {
      filters.push(<span key="more">and {item.filter_defs.length - size} more...</span>);
    }
    return filters;
  };

  const columns = [
    { title: 'Action', dataIndex: 'action' },
    { title: 'Parameters', render: (_, item) => getRowDescription(item) },
    { title: 'Filters', render: (_, item) => <Style.FiltersCell>{getRowFilters(item, 1)}</Style.FiltersCell> },
    { title: 'Rulesets', render: (_, item) => getRowRuleSets(item) },
    { title: 'Index', dataIndex: 'index' },
    {
      title: 'Ctrl',
      key: 'control',
      render: (_, record) => (
        <FilterEditKebab key={`${record.pk}-kebab`} data={record} lastIndex={count} needUpdate={fetchData} setExpand={setExpand} />
      ),
    },
  ];
  return (
    <div>
      <Helmet>
        <title>{`${STAMUS} - Policies`}</title>
      </Helmet>
      <Table
        data-test="policies-table"
        rowKey={item => item.pk}
        style={{ marginTop: '10px', marginBottom: '10px' }}
        size="small"
        loading={loading}
        dataSource={data}
        columns={columns}
        expandable={{
          columnWidth: 5,
          expandRowByClick: expand,
          expandedRowRender: item => <ActionItem filters={getRowFilters(item)} expandedRulesets={getRowRuleSets(item)} data={item} />,
          rowExpandable: () => true,
        }}
        pagination={{
          current: pagination.current,
          pageSize: pagination.pageSize,
          total: count,
          showSizeChanger: true,
          onChange: handleTableChange,
        }}
      />
    </div>
  );
};

export default PoliciesPage;
