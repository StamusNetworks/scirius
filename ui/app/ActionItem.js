import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { CheckCircleOutlined, CloseCircleOutlined, SafetyOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import * as config from 'config/Api';
import { buildFilterParams } from 'buildFilterParams';
import FilterEditKebab from 'ui/components/FilterEditKebab';

const ActionItemContainer = styled.div` 
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  grid-gap: 20px;
`

const Actionitem = styled.div`
  display: grid;
  grid-gap: 5px;
  justify-items: center;
`

const ActionSubItemOne = styled.div`
  display: grid;
  grid-template-columns: min-content 1fr;
  grid-column-gap: 10px;
  align-items: center;
  font-size: 14px;
`

const ActionSubItemTwo = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  grid-gap: 15px;
`

const ActionSubItemTwoItem = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  column-gap: 5px;
  align-items: center;
`

export default class ActionItem extends React.Component {
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
      <ActionItemContainer>
          {this.state.data &&
            this.state.data.map((item) => (
              <Actionitem key={item.key}>
                <ActionSubItemOne>
                  <SafetyOutlined style={{ fontSize: '21px', color: '#005792' }} />
                  <span>{item.key}</span>
                </ActionSubItemOne>
                <ActionSubItemTwo>
                    <ActionSubItemTwoItem>
                      <CheckCircleOutlined style={{ fontSize: '18px', color: '#3f9c35' }} />
                      <span>{item.seen.value}</span>
                    </ActionSubItemTwoItem>
                    <ActionSubItemTwoItem>
                      <CloseCircleOutlined style={{ fontSize: '18px', color: '#cc0000' }} />
                      <span>{item.drop.value}</span>
                    </ActionSubItemTwoItem>
                </ActionSubItemTwo>
              </Actionitem>
            ))}
        </ActionItemContainer>
    );
  }
}
ActionItem.propTypes = {
  data: PropTypes.any,
  needUpdate: PropTypes.any,
  last_index: PropTypes.any,
  switchPage: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
};
