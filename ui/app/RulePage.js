/* eslint-disable react/no-access-state-in-setstate */
import React from 'react';

import { Empty, List, Modal, Spin, Tabs } from 'antd';
import axios from 'axios';
import { cloneDeep } from 'lodash';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import * as config from 'config/Api';
import { buildQFilter } from 'ui/buildQFilter';
import EventValue from 'ui/components/EventValue';
import RuleEditKebab from 'ui/components/RuleEditKebab';
import { Signature } from 'ui/components/Signature';
import SignatureFlow from 'ui/components/SignatureFlow';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import { withStore } from 'ui/mobx/RootStoreProvider';
import { SignatureTimeline } from 'ui/pages/Signatures/components';
import Filter from 'ui/utils/Filter';

import { updateHitsStats } from './helpers/updateHitsStats';
import HuntStat from './HuntStat';
import RuleStatus from './RuleStatus';

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
    this.state = {
      rule: cloneDeep(this.props.rule),
      sid: this.props.sid,
      rule_status: undefined,
      toggle: { show: false, action: 'Disable' },
      extinfo: { http: false, dns: false, tls: false },
      moreResults: [],
      moreModal: null,
    };
    this.updateRuleState = this.updateRuleState.bind(this);
    this.fetchRuleStatus = this.fetchRuleStatus.bind(this);
    this.updateRuleStatus = this.updateRuleStatus.bind(this);
    this.updateExtInfo = this.updateExtInfo.bind(this);
  }

  componentDidMount() {
    const { rule, sid } = this.state;
    const qfilter = buildQFilter(this.props.filters, this.props.store.commonStore.systemSettings);
    const { filterParams } = this.props;
    if (typeof rule !== 'undefined') {
      updateHitsStats([rule], filterParams, this.updateRuleState, qfilter, this.props.store.tenantStore.tenant);
      axios
        .get(
          `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=app_proto&${filterParams}&sid=${this.props.rule.sid}&alert=${this.props.store.commonStore.eventTypes.alert}&stamus=${this.props.store.commonStore.eventTypes.stamus}&discovery=${this.props.store.commonStore.eventTypes.discovery}`,
        )
        .then(res => {
          this.updateExtInfo(res.data);
        });
      this.fetchRuleStatus(rule.sid);
    } else {
      axios
        .get(`${config.API_URL}${config.RULE_PATH}${sid}`)
        .then(res => {
          updateHitsStats([res.data], filterParams, this.updateRuleState, qfilter, this.props.store.tenantStore.tenant);
          axios
            .get(
              `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=app_proto&${filterParams}&sid=${sid}&alert=${this.props.store.commonStore.eventTypes.alert}&stamus=${this.props.store.commonStore.eventTypes.stamus}&discovery=${this.props.store.commonStore.eventTypes.discovery}`,
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
    const qfilter = buildQFilter(this.props.filters, this.props.store.commonStore.systemSettings);
    if (
      JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams) ||
      JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)
    ) {
      if (this.state.rule) {
        const rule = cloneDeep(this.state.rule);
        updateHitsStats([rule], this.props.filterParams, this.updateRuleState, qfilter, this.props.store.tenantStore.tenant);
      }
    }
  }

  loadMore = async (item, httpRequest) => {
    const data = await httpRequest;
    this.setState({ ...this.state, moreModal: item, moreResults: data });
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
          res.data[key].content = key in rescontent.data ? rescontent.data[key] : { 0: 'Rule not included in Ruleset' };
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
    const items = [];
    if (this.state.rule?.versions?.length > 1) {
      this.state.rule.versions.forEach((version, i) => {
        items.push({
          key: i,
          label: `Version ${version.version === 0 ? '< 39' : version.version}`,
          children: <Signature rule={version} id={version.id} />,
        });
      });
    }
    return (
      <div>
        <Spin spinning={this.state.rule === undefined}>
          {this.state.rule === null && <Empty description="Signature not found" style={{ padding: '3rem 0' }} />}
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
                  {this.state.rule?.versions?.length === 1 && <Signature rule={this.state.rule.versions[0]} />}
                  {this.state.rule?.versions?.length > 1 && <Tabs defaultActiveKey="1" items={items} />}
                </div>

                {this.state.rule.timeline && <SignatureTimeline sid={this.state.sid} />}

                {this.state.rule_status !== undefined && (
                  <Row>
                    {this.state.rule_status.map(rstatus => (
                      <RuleStatus key={rstatus.pk} rule_status={rstatus} />
                    ))}
                  </Row>
                )}
                <Row>
                  <HuntStat
                    title="Sources"
                    config={this.props.config}
                    filters={this.props.filters}
                    item="src_ip"
                    filterParams={this.props.filterParams}
                    addFilter={this.props.addFilter}
                    loadMore={this.loadMore}
                    eventTypes={this.props.store.commonStore.eventTypes}
                  />
                  <HuntStat
                    title="Destinations"
                    config={this.props.config}
                    filters={this.props.filters}
                    item="dest_ip"
                    filterParams={this.props.filterParams}
                    addFilter={this.props.addFilter}
                    loadMore={this.loadMore}
                    eventTypes={this.props.store.commonStore.eventTypes}
                  />
                  <HuntStat
                    title="Probes"
                    config={this.props.config}
                    filters={this.props.filters}
                    item="host"
                    filterParams={this.props.filterParams}
                    addFilter={this.props.addFilter}
                    loadMore={this.loadMore}
                    eventTypes={this.props.store.commonStore.eventTypes}
                  />
                </Row>
                {this.state.extinfo.http && (
                  <Row>
                    <HuntStat
                      title="Hostname"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="http.hostname"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                    <HuntStat
                      title="URL"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="http.url"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                    <HuntStat
                      title="User agent"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="http.http_user_agent"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                  </Row>
                )}
                {this.state.extinfo.dns && (
                  <Row>
                    <HuntStat
                      title="Name"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="dns.query.rrname"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                    <HuntStat
                      title="Type"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="dns.query.rrtype"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                  </Row>
                )}
                {this.state.extinfo.tls && (
                  <Row>
                    <HuntStat
                      title="Subject DN"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="tls.subject"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                    <HuntStat
                      // title="SNIe
                      config={this.props.config}
                      filters={this.props.filters}
                      item="tls.sni"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                    <HuntStat
                      title="Fingerprint"
                      config={this.props.config}
                      filters={this.props.filters}
                      item="tls.fingerprint"
                      filterParams={this.props.filterParams}
                      addFilter={this.props.addFilter}
                      loadMore={this.loadMore}
                      eventTypes={this.props.store.commonStore.eventTypes}
                    />
                  </Row>
                )}
              </div>
            </div>
          )}
          {this.state.rule && !this.state.rule.hits && <Empty description="No hits for this signature" style={{ padding: '3rem 0' }} />}
          <SignatureFlow rule={this.state.rule} />
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
                {this.state.moreModal && <EventValue filter={new Filter(this.state.moreModal, item.key)} count={item.doc_count} />}
              </List.Item>
            )}
          />
        </Modal>
      </div>
    );
  }
}
RulePage.propTypes = {
  sid: PropTypes.any,
  rule: PropTypes.any,
  filters: PropTypes.any,
  config: PropTypes.any,
  addFilter: PropTypes.any,
  rulesets: PropTypes.any,
  filterParams: PropTypes.object.isRequired,
  store: PropTypes.object,
};

export default withStore(RulePage);
