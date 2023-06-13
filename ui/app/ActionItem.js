import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import styled from 'styled-components';
import { Tabs } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined, SafetyOutlined } from '@ant-design/icons';

import * as config from 'config/Api';
import FilterEditKebab from 'ui/components/FilterEditKebab';
import UICard from 'ui/components/UIElements/UICard';
import { buildFilterParams } from 'ui/buildFilterParams';

const { TabPane } = Tabs;

const Styled = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
  grid-gap: 10px;
  padding-bottom: 10px;
`;

const ActionItemContainer = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, 200px);
  grid-gap: 20px;
  justify-items: center;
  &:not(:last-child) {
    margin-bottom: 20px;
  }
`;

const Actionitem = styled.div`
  display: grid;
  grid-gap: 5px;
  justify-items: center;
`;

const ActionSubItemOne = styled.div`
  display: grid;
  grid-template-columns: min-content 1fr;
  grid-column-gap: 10px;
  align-items: center;
  font-size: 14px;
`;

const ActionSubItemTwo = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  grid-gap: 15px;
`;

const ActionSubItemTwoItem = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  column-gap: 5px;
  align-items: center;
`;

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
      .then(res => {
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
    actionsMenu.push(<FilterEditKebab key={`${item.pk}-kebab`} data={item} last_index={this.props.last_index} needUpdate={this.props.needUpdate} />);

    return (
      <React.Fragment>
        <Tabs defaultActiveKey="1">
          <TabPane tab="Policy" key="1">
            <Styled>
              <UICard title="Filters">{this.props.filters}</UICard>
              <UICard title="Parameters">{this.props.expandedDescription}</UICard>
              <UICard title="Rulesets">{this.props.expandedRulesets}</UICard>
              <UICard title="Comment details">{this.props.expandedComment}</UICard>
            </Styled>
          </TabPane>
          <TabPane tab="Statistics" key="2">
            <ActionItemContainer>
              {this.state.data &&
                this.state.data.map(item => (
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
          </TabPane>
        </Tabs>
      </React.Fragment>
    );
  }
}
ActionItem.propTypes = {
  data: PropTypes.object,
  needUpdate: PropTypes.func,
  last_index: PropTypes.number,
  filterParams: PropTypes.object.isRequired,
  expandedDescription: PropTypes.element,
  filters: PropTypes.arrayOf(PropTypes.element),
  expandedRulesets: PropTypes.arrayOf(PropTypes.element),
  expandedComment: PropTypes.element,
};
