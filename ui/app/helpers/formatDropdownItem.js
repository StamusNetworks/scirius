import React from 'react';
import { Space } from 'antd';
import { FiltersList } from 'ui/maps/Filters';
import FilterValueType from 'ui/maps/FilterValueType';

const formatDropdownItem = ({ category, id, label, icon, children, valueType }) => {
  const filter = FiltersList.find(o => o.id === id && (o.category === category || o.category.includes(category)));
  return {
    // interface Option properties
    value: id,
    label: (
      <Space>
        {icon || filter?.icon}
        {label || filter?.title || id}
      </Space>
    ),
    disabled: false,
    children: children?.map(o => formatDropdownItem({ ...o, category })).filter(Boolean),

    // Custom properties
    title: label || filter?.title || id,
    valueType: valueType || filter?.valueType || FilterValueType.TEXT,
    validationType: filter?.validationType,
    category: filter?.category,
  };
};

export default formatDropdownItem;
