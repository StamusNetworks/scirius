/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/

import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Spin, Collapse } from 'antd';
import * as config from 'config/Api';
import ErrorHandler from 'ui/components/Error';
import FilterEditKebab from 'ui/components/FilterEditKebab';
import { CloseCircleOutlined, MailOutlined, MinusCircleOutlined, UploadOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import HuntPaginationRow from '../../HuntPaginationRow';
import ActionItem from '../../ActionItem';
import { actionsButtons, buildListUrlParams, createAction, closeAction, buildFilter } from '../../helpers/common';
const { Panel } = Collapse;

const PanelStyled = styled(Panel)`
  .ant-collapse-header {
    display: flex;
    flex: 1;
    flex-direction: row;
  }
`

const DescriptionItem = styled.div`
  padding: 0 10px;
`

const Count = styled.div`
  color: #FFF;
  font-size: 12px;
  background: #838383;
  margin-right: 10px;
  padding: 2px 7px;
`

export class ActionsPage extends React.Component {
  constructor(props) {
    super(props);
    this.state = { data: [], count: 0, rulesets: [] };

    this.buildFilter = buildFilter.bind(this);
    this.actionsButtons = actionsButtons.bind(this);
    this.createAction = createAction.bind(this);
    this.closeAction = closeAction.bind(this);
    this.fetchData = this.fetchData.bind(this);
    this.needUpdate = this.needUpdate.bind(this);
    this.buildListUrlParams = buildListUrlParams.bind(this);
    this.updateActionListState = this.updateActionListState.bind(this);
  }

  componentDidMount() {
    if (this.state.rulesets.length === 0) {
      axios.get(`${config.API_URL}${config.RULESET_PATH}`).then((res) => {
        const rulesets = {};
        for (let index = 0; index < res.data.results.length; index += 1) {
          rulesets[res.data.results[index].pk] = res.data.results[index];
        }
        this.setState({ rulesets });
      });
    }
    this.fetchData();
  }

  componentDidUpdate(prevProps) {
    if (JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams)) {
      this.fetchData();
    }
  }

  updateActionListState(rulesListState) {
    this.props.updateListState(rulesListState, () => this.fetchData());
  }

  // eslint-disable-next-line no-unused-vars
  fetchData() {
    const listParams = this.buildListUrlParams(this.props.rules_list);
    this.setState({ loading: true });
    axios
      .get(`${config.API_URL}${config.PROCESSING_PATH}?${listParams}`)
      .then((res) => {
        this.setState({ data: res.data.results, count: res.data.count, loading: false });
      })
      .catch(() => {
        this.setState({ loading: false });
      });
  }

  needUpdate() {
    this.fetchData();
  }

  render() {
    return (
      <div style={{ marginTop: 15 }}>
        <Spin spinning={this.state.loading} />
        <Collapse>
          {this.state.data.map(item => {

            // additional info
            const addinfo = [];
            for (let i = 0; i < item.filter_defs.length; i += 1) {
              let info = (
                <DescriptionItem>
                  {item.filter_defs[i].operator === 'different' && 'Not '}
                  {item.filter_defs[i].key}: {item.filter_defs[i].value}
                </DescriptionItem>
              );
              if (item.filter_defs[i].key === 'alert.signature_id' && item.filter_defs[i].msg) {
                info = (
                  <DescriptionItem>
                    {item.filter_defs[i].operator === 'different' && 'Not '}
                    {item.filter_defs[i].key}: {item.filter_defs[i].value} ({item.filter_defs[i].msg})
                  </DescriptionItem>
                );
              }
              addinfo.push(info);
            }
            if (Object.keys(this.state.rulesets).length > 0) {
              const rulesets = item.rulesets.map((item2) => (
                <DescriptionItem>Ruleset: {this.state.rulesets[item2].name}</DescriptionItem>
              ));
              addinfo.push(rulesets);
            }

            // description
            let description = [];
            if (item.action !== 'suppress') {
              description = Object.keys(item.options).map((option) => {
                if (option === 'all_tenants' || option === 'no_tenant' || option === 'tenants') return null;
                if (option === 'tenants_str') {
                  return (
                    <DescriptionItem>
                      <strong>tenants</strong>: {item.options[option].join()}
                    </DescriptionItem>
                  );
                }
                return (
                  <DescriptionItem>
                    <strong>{option}</strong>: {item.options[option]}
                  </DescriptionItem>
                );
              })
            }

            // actions menu
            const actionsMenu = [
              <Count>{item.index}</Count>,
            ];
            actionsMenu.push(
              <FilterEditKebab
                switchPage={this.props.switchPage}
                key={`${item.pk}-kebab`}
                data={item}
                last_index={this.state.count}
                needUpdate={this.needUpdate}
              />,
            );

            // icons
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

            if (item.imported) {
              icons.push(<UploadOutlined key="imported" title="Imported" className="glyphicon glyphicon-upload" />);
            }

            return (
              <PanelStyled
                key={item.pk}
                showArrow={false}
                extra={<div style={{ display: 'flex', flexDirection: 'row' }}>{actionsMenu}</div>}
                header={
                  <div style={{ display: 'flex', flex: 1, alignItems: 'center', columnGap: '20px' }}>
                    {icons && <div>{icons}</div>}
                    <div>{item.action}</div>
                    <div style={{ display: 'flex', flexDirection: 'row' }}>{description}</div>
                    <div style={{ display: 'flex' }}>{addinfo}</div>
                  </div>
                }>
                <ActionItem
                  switchPage={this.props.switchPage}
                  key={item.pk}
                  data={item}
                  last_index={this.state.count}
                  needUpdate={this.needUpdate}
                  rulesets={this.state.rulesets}
                  filterParams={this.props.filterParams}
                />
              </PanelStyled>
            );
          })}
        </Collapse>

        <div style={{ marginTop: 15 }}>
          <ErrorHandler>
            <HuntPaginationRow
              viewType="list"
              onPaginationChange={this.updateActionListState}
              itemsCount={this.state.count}
              itemsList={this.props.rules_list}
            />
          </ErrorHandler>
        </div>
      </div>
    );
  }
}

ActionsPage.propTypes = {
  rules_list: PropTypes.any,
  updateListState: PropTypes.func,
  switchPage: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
};
