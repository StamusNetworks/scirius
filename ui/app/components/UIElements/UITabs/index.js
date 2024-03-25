import React from 'react';

import { Tabs } from 'antd';
import PropTypes from 'prop-types';

const { TabPane } = Tabs;

const UITabs = ({ tabs, ...props }) => (
  <Tabs {...props}>
    {tabs.map(tab => (
      <TabPane {...tab} />
    ))}
  </Tabs>
);

UITabs.propTypes = {
  tabs: PropTypes.arrayOf(PropTypes.object),
};

export default UITabs;
