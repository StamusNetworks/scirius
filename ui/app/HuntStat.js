import React from 'react';
import PropTypes from 'prop-types';
import { Dropdown, List, Menu } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import axios from 'axios';
import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'ui/buildFilterParams';
import EventValue from 'ui/components/EventValue';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BOX_HEADER } from 'ui/constants/colors';
export default class HuntStat extends React.Component {
  constructor(props) {
    super(props);
    this.state = { data: [] };
    this.url = '';
    this.updateData = this.updateData.bind(this);
    this.addFilter = this.addFilter.bind(this);
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

  updateData() {
    const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
    const filterParams = buildFilterParams(this.props.filterParams);

    this.url = `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${this.props.item}&${filterParams}&page_size=30${qfilter}`;

    axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${this.props.item}&${filterParams}&page_size=5${qfilter}`).then(res => {
      this.setState({ data: res.data });
    });
  }

  addFilter(id, value, negated) {
    this.props.addFilter({ id, value, negated });
  }

  menu = (
    <Menu>
      <Menu.Item onClick={() => this.props.loadMore(this.props.item, this.url)} data-toggle="modal">
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
                    <a className="ant-dropdown-link" style={{ color: '#fff' }} onClick={e => e.preventDefault()}>
                      <MenuOutlined />
                    </a>
                  </Dropdown>
                )}
              </div>
            </div>
          }
          headStyle={{ background: COLOR_BOX_HEADER, color: '#FFF', textAlign: 'center' }}
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
  addFilter: PropTypes.func,
  filterParams: PropTypes.object.isRequired,
};
