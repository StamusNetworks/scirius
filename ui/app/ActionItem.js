import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Menu } from 'antd';
import { CloseCircleOutlined, MailOutlined, MinusCircleOutlined, UploadOutlined } from '@ant-design/icons';
import * as config from 'config/Api';
import { buildFilterParams } from 'buildFilterParams';
import FilterEditKebab from 'ui/components/FilterEditKebab';

export default class FilterItem extends React.Component {
  constructor(props) {
    super(props);
    // eslint-disable-next-line react/no-unused-state
    this.state = { data: undefined, loading: true };
  }

  componentDidMount() {
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams)) {
      this.fetchData();
    }
  }

  fetchData() {
    // eslint-disable-next-line react/no-unused-state
    this.setState({ loading: true });
    const filterParams = buildFilterParams(this.props.filterParams);
    axios
      .get(`${config.API_URL + config.ES_BASE_PATH}poststats_summary/?value=rule_filter_${this.props.data.pk}&${filterParams}`)
      .then((res) => {
        // eslint-disable-next-line react/no-unused-state
        this.setState({ data: res.data, loading: false });
      })
      .catch(() => {
        // eslint-disable-next-line react/no-unused-state
        this.setState({ loading: false });
      });
  }

  render() {
    const item = this.props.data;
    const addinfo = [];
    for (let i = 0; i < item.filter_defs.length; i += 1) {
      let info = (
        <span key={`filter-${i}`}>
          <span>
            {item.filter_defs[i].operator === 'different' && 'Not '}
            {item.filter_defs[i].key}: {item.filter_defs[i].value}
          </span>
        </span>
      );
      if (item.filter_defs[i].key === 'alert.signature_id' && item.filter_defs[i].msg) {
        info = (
          <span key={`filter-${i}`}>
            <span>
              {item.filter_defs[i].operator === 'different' && 'Not '}
              {item.filter_defs[i].key}: {item.filter_defs[i].value} ({item.filter_defs[i].msg})
            </span>
          </span>
        );
      }
      addinfo.push(info);
    }
    if (Object.keys(this.props.rulesets).length > 0) {
      const rulesets = item.rulesets.map((item2) => (
        <span key={`${item2}-ruleset`}>
          <span>Ruleset: {this.props.rulesets[item2].name}</span>
        </span>
      ));
      addinfo.push(rulesets);
    }
    let description = '';
    if (item.action !== 'suppress') {
      description = (
        <ul className="list-inline">
          {Object.keys(item.options).map((option) => {
            if (option === 'all_tenants' || option === 'no_tenant' || option === 'tenants') return null;
            if (option === 'tenants_str') {
              return (
                <li key="tenants_str">
                  <strong>tenants</strong>: {item.options[option].join()}
                </li>
              );
            }
            return (
              <li key={option}>
                <strong>{option}</strong>: {item.options[option]}
              </li>
            );
          })}
        </ul>
      );
    }
    let icon;
    const icons = [];
    switch (item.action) {
      case 'suppress':
        icon = <CloseCircleOutlined style={{ fontSize: '27px' }} key="suppress" />;
        break;
      case 'threshold':
        icon = <MinusCircleOutlined style={{ fontSize: '27px' }} key="threshold" />;
        break;
      case 'tag':
        icon = <MailOutlined style={{ fontSize: '27px' }} key="tag" />;
        break;
      case 'tagkeep':
        icon = <MailOutlined style={{ fontSize: '27px' }} key="tagkeep" />;
        break;
      default:
        icon = <MailOutlined style={{ fontSize: '27px' }} key="tag" />;
        break;
    }
    icons.push(icon);

    const actionsMenu = [
      <span key={`${item.pk}-index`} className="badge badge-default">
        {item.index}
      </span>,
    ];
    actionsMenu.push(
      <FilterEditKebab
        switchPage={this.props.switchPage}
        key={`${item.pk}-kebab`}
        data={item}
        last_index={this.props.last_index}
        needUpdate={this.props.needUpdate}
      />,
    );

    if (item.imported) {
      icons.push(<UploadOutlined key="imported" title="Imported" className="glyphicon glyphicon-upload" />);
    }

    return (
      <Menu mode="inline">
        <Menu.SubMenu
          key={`${item.pk}-listitem`}
          icon={icons}
          title={
            <div style={{ display: 'flex' }}>
              <span>{item.action}</span>
              <span>{description}</span>
              <span style={{ display: 'flex' }}>{addinfo}</span>
              <span>{actionsMenu}</span>
            </div>
          }
        >
          {this.state.data &&
            this.state.data.map((item2) => (
              <Menu.Item key={item2.key} style={{ height: '100%' }}>
                <div className="card-pf card-pf-accented card-pf-aggregate-status">
                  <h2 className="card-pf-title">
                    <span className="fa fa-shield" />
                    {item2.key}
                  </h2>
                  <div className="card-pf-body">
                    <p className="card-pf-aggregate-status-notifications">
                      <span className="card-pf-aggregate-status-notification">
                        <span className="pficon pficon-ok" />
                        {item2.seen.value}
                      </span>
                      <span className="card-pf-aggregate-status-notification">
                        <span className="pficon pficon-error-circle-o" />
                        {item2.drop.value}
                      </span>
                    </p>
                  </div>
                </div>
              </Menu.Item>
            ))}
        </Menu.SubMenu>
      </Menu>
    );
  }
}
FilterItem.propTypes = {
  data: PropTypes.any,
  rulesets: PropTypes.any,
  needUpdate: PropTypes.any,
  last_index: PropTypes.any,
  switchPage: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
};
