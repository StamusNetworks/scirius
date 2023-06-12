import React from 'react';
import PropTypes from 'prop-types';
import { Dropdown, List, Menu } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import { toJS } from 'mobx';

import EventValue from 'ui/components/EventValue';
import UICard from 'ui/components/UIElements/UICard';
import { buildQFilter } from 'ui/buildQFilter';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import { withStore } from 'ui/mobx/RootStoreProvider';

class HuntStat extends React.Component {
  constructor(props) {
    super(props);
    this.state = { data: [] };
    this.url = '';
    this.updateData = this.updateData.bind(this);
    this.qfilter = '';
  }

  componentDidMount() {
    this.updateData();
  }

  componentDidUpdate(prevProps) {
    if (
      JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) ||
      JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)
    ) {
      this.updateData();
    }
  }

  async updateData() {
    this.qfilter = buildQFilter(this.props.store.commonStore.getFilters(), toJS(this.props.store.commonStore.systemSettings)) || '';
    const data = await this.props.store.esStore.fetchFieldStats(this.props.item, 5, this.qfilter);
    this.setState({ data });
  }

  addFilter = (id, value, negated) => {
    this.props.store.commonStore.addFilter({ id, value, negated });
  };

  menu = (
    <Menu>
      <Menu.Item
        onClick={() => {
          this.props.loadMore(this.props.item, this.props.store.esStore.fetchFieldStats(this.props.item, 30, this.qfilter));
        }}
        data-toggle="modal"
      >
        Load more results
      </Menu.Item>
    </Menu>
  );

  render() {
    if (this.state.data && this.state.data.length) {
      return (
        <UICard
          title={
            <div style={{ display: 'grid', gridTemplateColumns: '1fr min-content' }}>
              <div>{this.props.title}</div>
              <div>
                {this.state.data.length === 5 && (
                  <Dropdown id={`more-${this.props.item}`} overlay={this.menu} trigger={['click']}>
                    <a className="ant-dropdown-link" style={{ color: COLOR_BRAND_BLUE }} onClick={e => e.preventDefault()}>
                      <MenuOutlined />
                    </a>
                  </Dropdown>
                )}
              </div>
            </div>
          }
          headStyle={{ color: COLOR_BRAND_BLUE, textAlign: 'center' }}
          noPadding
        >
          <List
            size="small"
            header={null}
            footer={null}
            dataSource={this.state.data}
            renderItem={item => (
              <List.Item key={item.key} style={{ padding: '8px 10px' }}>
                <EventValue field={this.props.item} value={item.key} addFilter={this.addFilter} right_info={item.doc_count} />
              </List.Item>
            )}
          />
        </UICard>
      );
    }
    return null;
  }
}
HuntStat.propTypes = {
  title: PropTypes.any,
  filters: PropTypes.any,
  item: PropTypes.any,
  systemSettings: PropTypes.any,
  loadMore: PropTypes.func,
  filterParams: PropTypes.object.isRequired,
  store: PropTypes.object,
};

export default withStore(HuntStat);
