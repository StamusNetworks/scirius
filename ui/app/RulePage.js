/* eslint-disable react/no-access-state-in-setstate */
import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import axios from 'axios';
import { List, Modal, Spin } from 'antd';
import { cloneDeep } from 'lodash';
import styled from 'styled-components';
import { createStructuredSelector } from 'reselect';

import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'ui/buildFilterParams';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import SciriusChart from 'ui/components/SciriusChart';
import EventValue from 'ui/components/EventValue';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import { makeSelectEventTypes } from 'ui/containers/HuntApp/stores/global';
import RuleStatus from './RuleStatus';
import HuntStat from './HuntStat';
import { updateHitsStats } from './helpers/updateHitsStats';
import { SigContent } from './RuleInList';

const Row = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 0.5fr));
  grid-gap: 10px;
  margin-bottom: 10px;
`;

const RuleMsg = styled.div`
  font-size: 24px;
  font-weight: 300;
  display: grid;
  grid-template-columns: 1fr max-content min-content;
  grid-column-gap: 30px;
  padding: 10px;
`;

const RuleHits = styled.div`
  color: ${COLOR_BRAND_BLUE};
  padding: 0 10px;
`;

class RulePage extends React.Component {
  constructor(props) {
    super(props);
    const rule = cloneDeep(this.props.rule);
    if (typeof rule === 'number') {
      this.state = {
        rule: undefined,
        rule_status: undefined,
        sid: rule,
        toggle: { show: false, action: 'Disable' },
        extinfo: { http: false, dns: false, tls: false },
        moreResults: [],
        moreModal: null,
      };
    } else {
      rule.timeline = undefined;
      this.state = {
        rule,
        rule_status: undefined,
        sid: rule.sid,
        toggle: { show: false, action: 'Disable' },
        extinfo: { http: false, dns: false, tls: false },
        moreResults: [],
        moreModal: null,
      };
    }
    this.updateRuleState = this.updateRuleState.bind(this);
    this.fetchRuleStatus = this.fetchRuleStatus.bind(this);
    this.updateRuleStatus = this.updateRuleStatus.bind(this);
    this.updateExtInfo = this.updateExtInfo.bind(this);
  }

  componentDidMount() {
    const { rule, sid } = this.state;
    const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
    const filterParams = buildFilterParams(this.props.filterParams);
    if (typeof rule !== 'undefined') {
      updateHitsStats([rule], filterParams, this.updateRuleState, qfilter);
      axios
        .get(
          `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=app_proto&${filterParams}&sid=${this.props.rule.sid}&alert=${this.props.eventTypes.alert}&stamus=${this.props.eventTypes.stamus}&discovery=${this.props.eventTypes.discovery}`,
        )
        .then(res => {
          this.updateExtInfo(res.data);
        });
      this.fetchRuleStatus(rule.sid);
    } else {
      axios
        .get(`${config.API_URL}${config.RULE_PATH}${sid}/?highlight=true`)
        .then(res => {
          updateHitsStats([res.data], filterParams, this.updateRuleState, qfilter);
          axios
            .get(
              `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=app_proto&${filterParams}&sid=${sid}&alert=${this.props.eventTypes.alert}&stamus=${this.props.eventTypes.stamus}&discovery=${this.props.eventTypes.discovery}`,
            )
            .then(res2 => {
              this.updateExtInfo(res2.data);
            });
        })
        .catch(error => {
          if (error.response.status === 404) {
            this.setState({ errors: { signature: ['Signature not found'] }, rule: null });
            return;
          }
          this.setState({ rule: null });
        });
      this.fetchRuleStatus(sid);
    }
  }

  componentDidUpdate(prevProps) {
    const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
    if (
      JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) ||
      JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)
    ) {
      if (this.state.rule) {
        const rule = cloneDeep(this.state.rule);
        const filterParams = buildFilterParams(this.props.filterParams);
        updateHitsStats([rule], filterParams, this.updateRuleState, qfilter);
      }
    }
  }

  loadMore = (item, url) => {
    axios.get(url).then(json => {
      this.setState({ ...this.state, moreModal: item, moreResults: json.data });
    });
  };

  hideMoreModal = () => this.setState({ ...this.state, moreModal: null });

  updateExtInfo(data) {
    if (!data) {
      return;
    }
    const { extinfo } = this.state;
    for (let i = 0; i < data.length; i += 1) {
      if (data[i].key === 'dns') {
        extinfo.dns = true;
      }
      if (data[i].key === 'http') {
        extinfo.http = true;
      }
      if (data[i].key === 'tls') {
        extinfo.tls = true;
      }
    }
    this.setState({ extinfo });
  }

  updateRuleStatus() {
    return this.fetchRuleStatus(this.state.rule.sid);
  }

  fetchRuleStatus(sid) {
    axios
      .all([
        axios.get(`${config.API_URL + config.RULE_PATH + sid}/status/`),
        axios.get(`${config.API_URL + config.RULE_PATH + sid}/content/?highlight=1`),
        axios.get(`${config.API_URL + config.RULE_PATH + sid}/references/`),
      ])
      .then(([res, rescontent, referencesContent]) => {
        const rstatus = [];

        Object.keys(res.data).forEach(key => {
          res.data[key].pk = key;
          res.data[key].content = key in rescontent.data ? rescontent.data[key] : 'Rule not included in Ruleset';
          rstatus.push(res.data[key]);
        });

        this.setState({ rule_status: rstatus });
        this.setState({ rule_references: referencesContent.data });
      });
  }

  updateRuleState(rule) {
    this.setState({ rule: rule[0] });
  }

  render() {
    return (
      <div>
        <Spin spinning={this.state.rule === undefined}>
          {this.state.rule && (
            <div>
              <RuleMsg>
                <div>{this.state.rule.msg}</div>
                {this.state.rule && this.state.rule.hits !== undefined && (
                  <RuleHits>
                    {this.state.rule.hits} hit{this.state.rule.hits > 1 && 's'}
                  </RuleHits>
                )}
                <RuleEditKebab config={this.state} rulesets={this.props.rulesets} refresh_callback={this.updateRuleStatus} />
              </RuleMsg>

              <div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr max-content', gridGap: '10px', marginBottom: '10px' }}>
                  {/* eslint-disable-next-line react/no-danger */}
                  <SigContent dangerouslySetInnerHTML={{ __html: this.state.rule.content }} />

                  {this.state.rule_references && this.state.rule_references.length > 0 && (
                    <UICard
                      title={<div>References</div>}
                      headStyle={{ color: COLOR_BRAND_BLUE, textAlign: 'center' }}
                      bodyStyle={{ display: 'grid', padding: '8px 10px' }}
                      noPadding
                    >
                      {this.state.rule_references.map(reference => {
                        if (reference.url !== undefined) {
                          return (
                            <a key={reference.url} href={reference.url} target="_blank">{`${
                              reference.key[0].toUpperCase() + reference.key.substring(1)
                            }: ${reference.value.substring(0, 45)}...`}</a>
                          );
                        }
                        return null;
                      })}
                    </UICard>
                  )}
                </div>

                {this.state.rule.timeline && (
                  <SciriusChart
                    data={this.state.rule.timeline}
                    axis={{ x: { min: this.props.filterParams.fromDate, max: this.props.filterParams.toDate } }}
                    legend={{ show: false }}
                    padding={{ bottom: 10 }}
                  />
                )}

                {this.state.rule_status !== undefined && (
                  <Row>
                    {this.state.rule_status.map(rstatus => (
                      <RuleStatus rule={this.state.rule} key={rstatus.pk} rule_status={rstatus} />
                    ))}
                  </Row>
                )}
                <Row>
                  <HuntStat
                    systemSettings={this.state.systemSettings}
                    title="Sources"
                    rule={this.state.rule}
                    config={this.props.config}
                    filters={this.props.filters}
                    item="src_ip"
                    filterParams={this.props.filterParams}
                    addFilter={this.props.addFilter}
                    loadMore={this.loadMore}
                  />
                  <HuntStat
                    title="Destinations"
                    rule={this.state.rule}
                    config={this.props.config}
                    filters={this.props.filters}
                    item="dest_ip"
                    filterParams={this.props.filterParams}
                    addFilter={this.props.addFilter}
                    loadMore={this.loadMore}
                  />
                  <HuntStat
                    title="Probes"
                    rule={this.state.rule}
                    config={this.props.config}
                    filters={this.props.filters}
                    item="host"
                    filterParams={this.props.filterParams}
                    addFilter={this.props.addFilter}
                    loadMore={this.loadMore}
                  />
                </Row>
                {this.state.extinfo.http && (
                  <Row>
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="Hostname"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="http.hostname"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="URL"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="http.url"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="User agent"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="http.http_user_agent"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                  </Row>
                )}
                {this.state.extinfo.dns && (
                  <Row>
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="Name"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="dns.query.rrname"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="Type"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="dns.query.rrtype"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                  </Row>
                )}
                {this.state.extinfo.tls && (
                  <Row>
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="Subject DN"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="tls.subject"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="SNI"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="tls.sni"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                    <HuntStat
                      systemSettings={this.state.systemSettings}
                      title="Fingerprint"
                      rule={this.state.rule}
                      config={this.props.config}
                      filters={this.props.filters}
                      item="tls.fingerprint"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                    />
                  </Row>
                )}
              </div>
            </div>
          )}
        </Spin>

        <Modal
          visible={!(this.state.moreModal === null)}
          title="More results"
          footer={null}
          onCancel={() => {
            this.hideMoreModal();
          }}
        >
          <List
            size="small"
            header={null}
            footer={null}
            dataSource={this.state.moreResults}
            renderItem={item => (
              <List.Item key={item.key}>
                {this.state.moreModal && (
                  <EventValue field={this.state.moreModal} value={item.key} addFilter={this.props.addFilter} right_info={item.doc_count} />
                )}
              </List.Item>
            )}
          />
        </Modal>
      </div>
    );
  }
}
RulePage.propTypes = {
  rule: PropTypes.any,
  systemSettings: PropTypes.any,
  filters: PropTypes.any,
  config: PropTypes.any,
  addFilter: PropTypes.any,
  rulesets: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  eventTypes: PropTypes.object,
};

const mapStateToProps = createStructuredSelector({
  eventTypes: makeSelectEventTypes(),
});

export default connect(mapStateToProps)(RulePage);
