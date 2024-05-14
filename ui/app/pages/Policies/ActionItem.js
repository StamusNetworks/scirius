import React, { useState } from 'react';

import { CheckCircleOutlined, CloseCircleOutlined, SafetyOutlined } from '@ant-design/icons';
import { Tabs, Spin } from 'antd';
import moment from 'moment';
import PropTypes from 'prop-types';

import UICard from 'ui/components/UIElements/UICard';
import constants from 'ui/constants';
import notify from 'ui/helpers/notify';
import useAutorun from 'ui/helpers/useAutorun';
import PolicyParameters from 'ui/pages/Policies/PolicyParameters';
import API from 'ui/services/API';

import * as Style from './style';

const { TabPane } = Tabs;

function ActionItem({ data, filters, expandedRulesets }) {
  const [actionData, setActionData] = useState();
  const [loadingStats, setLoadingStats] = useState(false);

  useAutorun(() => {
    fetchData();
  }, [data.pk]);

  const fetchData = async () => {
    setLoadingStats(true);
    try {
      const res = await API.fetchPoliciesData({ value: `rule_filter_${data.pk}` });
      setActionData(res.data);
    } catch {
      notify('Fail to fetch policies statistics');
    } finally {
      setLoadingStats(false);
    }
  };

  return (
    <React.Fragment>
      <Tabs defaultActiveKey="1">
        <TabPane tab="Policy" key="1">
          <Style.PolicyContainer>
            <UICard title="Filters">{filters}</UICard>
            <UICard title="Parameters">
              <PolicyParameters options={data.options} />
            </UICard>
            <UICard title="Rulesets">{expandedRulesets}</UICard>
            <UICard title="Comment details">
              <Style.DescriptionItem>
                <b>username: </b>
                {data.username}
              </Style.DescriptionItem>
              <Style.DescriptionItem>
                <b>creation date: </b>
                {moment(data.creation_date).format(constants.DATE_TIME_FORMAT)}
              </Style.DescriptionItem>
              <Style.DescriptionItem>
                <b>comment: </b>
                {data.comment}
              </Style.DescriptionItem>
            </UICard>
          </Style.PolicyContainer>
        </TabPane>
        <TabPane tab="Statistics" key="2">
          <Style.ActionItemContainer>
            {loadingStats ? (
              <Spin />
            ) : (
              actionData &&
              actionData.map(item => (
                <Style.Actionitem key={item.key}>
                  <Style.ActionSubItemOne>
                    <SafetyOutlined style={{ fontSize: '21px', color: '#005792' }} />
                    <span>{item.key}</span>
                  </Style.ActionSubItemOne>
                  <Style.ActionSubItemTwo>
                    <Style.ActionSubItemTwoItem>
                      <CheckCircleOutlined style={{ fontSize: '18px', color: '#3f9c35' }} />
                      <span>{item.seen.value}</span>
                    </Style.ActionSubItemTwoItem>
                    <Style.ActionSubItemTwoItem>
                      <CloseCircleOutlined style={{ fontSize: '18px', color: '#cc0000' }} />
                      <span>{item.drop.value}</span>
                    </Style.ActionSubItemTwoItem>
                  </Style.ActionSubItemTwo>
                </Style.Actionitem>
              ))
            )}
          </Style.ActionItemContainer>
        </TabPane>
      </Tabs>
    </React.Fragment>
  );
}

ActionItem.propTypes = {
  data: PropTypes.object.isRequired,
  filters: PropTypes.arrayOf(PropTypes.element),
  expandedRulesets: PropTypes.arrayOf(PropTypes.element),
};

export default ActionItem;
