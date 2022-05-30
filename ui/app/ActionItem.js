import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
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



    return (
      <>
          {this.state.data &&
            this.state.data.map((item2) => (
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
            ))}
        </>
    );
  }
}
FilterItem.propTypes = {
  data: PropTypes.any,
  needUpdate: PropTypes.any,
  last_index: PropTypes.any,
  switchPage: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
};
