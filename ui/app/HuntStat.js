import React from 'react';
import PropTypes from 'prop-types';
import { Dropdown, List, Menu } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import axios from 'axios';
import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'buildFilterParams';
import EventValue from 'ui/components/EventValue';

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

    axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${this.props.item}&${filterParams}&page_size=5${qfilter}`).then((res) => {
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
    let colVal = 'col-md-3';
    if (this.props.col) {
      colVal = `col-md-${this.props.col}`;
    }
    if (this.state.data && this.state.data.length) {
      return (
        <div className={colVal}>
          <h3
            className="hunt-stat-title truncate-overflow"
            data-toggle="tooltip"
            title={this.props.title}
            style={{ display: 'flex', justifyContent: 'space-between' }}
          >
            <span>{this.props.title}</span>
            {this.state.data.length === 5 && (
              <Dropdown id={`more-${this.props.item}`} overlay={this.menu} trigger={['click']}>
                <a className="ant-dropdown-link" onClick={(e) => e.preventDefault()}>
                  <MenuOutlined />
                </a>
              </Dropdown>
            )}
          </h3>
          <div className="hunt-stat-body">
            <List
              size="small"
              header={null}
              footer={null}
              dataSource={this.state.data}
              renderItem={(item) => (
                <List.Item key={item.key}>
                  <EventValue
                    field={this.props.item}
                    value={item.key}
                    addFilter={this.addFilter}
                    right_info={<span className="badge">{item.doc_count}</span>}
                  />
                </List.Item>
              )}
            />
          </div>
        </div>
      );
    }
    return null;
  }
}
HuntStat.propTypes = {
  title: PropTypes.any,
  filters: PropTypes.any,
  col: PropTypes.any,
  item: PropTypes.any,
  systemSettings: PropTypes.any,
  loadMore: PropTypes.func,
  addFilter: PropTypes.func,
  filterParams: PropTypes.object.isRequired,
};
