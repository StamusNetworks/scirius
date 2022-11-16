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
import { Dropdown, Empty, Menu, Modal, Spin, Row, Col, message } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import { WidthProvider, Responsive } from 'react-grid-layout';
import store from 'store';
import md5 from 'md5';
import map from 'lodash/map';
import { Helmet } from 'react-helmet';
import { STAMUS } from 'ui/config';
import find from 'lodash/find';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import * as config from 'config/Api';
import { dashboard } from 'ui/config/Dashboard';
import { buildQFilter } from 'ui/buildQFilter';
import { buildFilterParams } from 'ui/buildFilterParams';
import { sections } from 'ui/constants';
import UICard from 'ui/components/UIElements/UICard';
import { COLOR_BRAND_BLUE } from 'ui/constants/colors';
import EventValue from 'ui/components/EventValue';
import ErrorHandler from 'ui/components/Error';
import Filters from 'ui/components/Filters';
import globalSelectors from 'ui/containers/App/selectors';
import { makeSelectFilterParams } from 'ui/containers/HuntApp/stores/filterParams';
import { withPermissions } from 'ui/containers/HuntApp/stores/withPermissions';
import downloadData from 'ui/helpers/downloadData';
import HuntTimeline from '../../HuntTimeline';
import HuntTrend from '../../HuntTrend';
import { actionsButtons, loadActions, createAction, closeAction } from '../../helpers/common';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';
import copyTextToClipboard from '../../helpers/copyTextToClipboard';
import { makeSelectAlertTag, makeSelectGlobalFilters } from '../../containers/HuntApp/stores/global';
import '../../../../rules/static/rules/c3.min.css';

const ResponsiveReactGridLayout = WidthProvider(Responsive);

export class HuntDashboard extends React.Component {
  constructor(props) {
    super(props);

    let onlyHits = localStorage.getItem('rules_list.only_hits');
    if (!onlyHits) {
      onlyHits = false;
    }

    this.panelAutoresize = false;
    this.panelState = {};
    this.panelsLoaded = 0;
    this.panelsBooted = 'no';
    this.panelsAdjusted = false;
    this.breakPointChanged = false;
    this.storedMicroLayout = [];
    this.storedMacroLayout = [];
    this.qFilter = '';
    this.filters = '';

    const huntFilters = store.get('huntFilters');
    const rulesFilters = typeof huntFilters !== 'undefined' && typeof huntFilters.dashboard !== 'undefined' ? huntFilters.dashboard.data : [];
    let chartTarget = store.get('chartTarget') === true;

    if (!chartTarget && !this.props.user.permissions.includes('rules.configuration_view')) {
      chartTarget = true;
    }

    this.state = {
      load: Object.keys(dashboard.sections),
      // load: ['basic'],
      breakPoint: 'lg',
      dashboard: this.extendDefaultPanels(),
      rules: [],
      sources: [],
      rulesets: [],
      rules_count: 0,
      view: 'rules_list',
      onlyHits,
      action: { view: false, type: 'suppress' },
      net_error: undefined,
      rulesFilters,
      supported_actions: [],
      moreModal: null,
      moreResults: [],
      editMode: false,
      chartTarget,
      copyMode: false,
      hoveredItem: null,
      copiedItem: '',
    };
    this.actionsButtons = actionsButtons.bind(this);
    this.createAction = createAction.bind(this);
    this.closeAction = closeAction.bind(this);
    this.loadActions = loadActions.bind(this);
    this.fetchData = () => {};
  }

  componentDidMount() {
    if (this.state.rulesets.length === 0) {
      axios.get(config.API_URL + config.RULESET_PATH).then(res => {
        this.setState({ rulesets: res.data.results });
      });
    }
    const huntFilters = store.get('huntFilters');
    axios.get(config.API_URL + config.HUNT_FILTER_PATH).then(res => {
      const fdata = [];
      for (let i = 0; i < res.data.length; i += 1) {
        /* Only ES filter are allowed for Alert page */
        if (['filter'].indexOf(res.data[i].queryType) !== -1) {
          if (res.data[i].filterType !== 'hunt') {
            fdata.push(res.data[i]);
          }
        }
      }
      const currentCheckSum = md5(JSON.stringify(fdata));
      if (typeof huntFilters === 'undefined' || typeof huntFilters.dashboard === 'undefined' || huntFilters.dashboard.checkSum !== currentCheckSum) {
        store.set('huntFilters', {
          ...huntFilters,
          dashboard: {
            checkSum: currentCheckSum,
            data: fdata,
          },
        });
        this.setState({ rulesFilters: fdata });
      }
    });

    window.addEventListener('resize', this.resizeWindow);

    if (this.props.filters.length && this.props.user.permissions.includes('rules.ruleset_policy_edit')) {
      this.loadActions(this.props.filters);
    }

    const detectspecialkeys = (e, keyDown) => {
      if (e.keyCode === 17) {
        if (this.state.copyMode !== keyDown) {
          this.setState({ copyMode: keyDown });
        }
      }
    };

    document.onkeydown = e => detectspecialkeys(e, true);
    document.onkeyup = e => detectspecialkeys(e, false);
  }

  componentDidUpdate(prevProps) {
    // An adjustment of the panels height is needed for their first proper placement
    if (this.panelsBooted === 'yes' && !this.panelsAdjusted) {
      this.panelsAdjusted = true;
      this.adjustPanelsHeight();
    }

    if (typeof this.props.systemSettings !== 'undefined') {
      this.qFilter = this.generateQFilter();
      this.storedMicroLayout = store.get('dashboardMicroLayout');
      this.storedMacroLayout = store.get('dashboardMacroLayout');
      // Initial booting of panels were moved here instead of componentDidMount, because of the undefined systemSettings in componentDidMount
      if (this.panelsBooted === 'no') {
        this.bootPanels();
      } else if (!this.filters.length) {
        this.filters = JSON.stringify(this.props.filters);
      } else if (
        this.panelsBooted !== 'booting' &&
        (this.filters !== JSON.stringify(this.props.filters) ||
          JSON.stringify(prevProps.filtersWithAlert) !== JSON.stringify(this.props.filtersWithAlert) ||
          JSON.stringify(prevProps.filterParams) !== JSON.stringify(this.props.filterParams))
      ) {
        this.filters = JSON.stringify(this.props.filters);
        this.bootPanels();
        if (this.props.user.permissions.includes('rules.ruleset_policy_edit')) {
          this.loadActions(this.props.filters);
        }
      }
    }
  }

  componentWillUnmount() {
    window.removeEventListener('resize', this.resizeWindow);
  }

  timeout = false;

  resizeWindow = e => {
    // Trigger a second resize, to work-around panels not rearranging
    if (e.huntEvent) {
      // work-around to prevent infinite resize
      return;
    }
    clearTimeout(this.timeout);
    this.timeout = setTimeout(() => {
      let evt;
      if (typeof Event === 'function') {
        // modern browsers
        evt = new Event('resize');
      } else {
        // for IE and other old browsers
        // causes deprecation warning on modern browsers
        evt = window.document.createEvent('UIEvents');
        evt.initUIEvent('resize', true, false, window, 0);
      }
      evt.huntEvent = true;
      window.dispatchEvent(evt);
    }, 250);
  };

  getBlockFromLS = (panel, block, breakPoint) => {
    let result = {};
    if (
      typeof this.storedMicroLayout !== 'undefined' &&
      typeof this.storedMicroLayout[panel] !== 'undefined' &&
      typeof this.storedMicroLayout[panel][breakPoint] !== 'undefined'
    ) {
      result = find(this.storedMicroLayout[panel][breakPoint], { i: block });
    }
    return result;
  };

  getPanelFromLS = panel => {
    let result = {};
    if (typeof this.storedMacroLayout !== 'undefined' && typeof this.storedMacroLayout[panel] !== 'undefined') {
      result = find(this.storedMacroLayout, { i: panel });
    }
    return result;
  };

  generateQFilter = () => {
    let qfilter = buildQFilter(this.props.filtersWithAlert, this.props.systemSettings);
    if (!qfilter) {
      qfilter = '';
    }
    return qfilter;
  };

  /* default panel properties should be extended with the stored equivalent into the localStorage */
  extendDefaultPanels = () => {
    const storedMacroLayout = store.get('dashboardMacroLayout');
    return Object.assign(
      {},
      ...Object.keys(dashboard.sections).map(k => {
        const storedPanel = find(storedMacroLayout, { i: k });
        if (typeof storedPanel === 'undefined') {
          return {
            [k]: {
              ...dashboard.sections[k],
            },
          };
        }

        return {
          [k]: {
            ...dashboard.sections[k],
            dimensions: {
              ...dashboard.sections[k].dimensions,
              y: storedPanel.y,
            },
          },
        };
      }),
    );
  };

  resetPanelHeight = (field, data = null) => ({
    [field]: {
      ...this.state.dashboard[field],
      items: [
        ...this.state.dashboard[field].items.map((z, i) => ({
          ...z,
          data,
          dimensions: {
            ...dashboard.sections[field].items[i].dimensions,
          },
        })),
      ],
      dimensions: {
        ...this.state.dashboard[field].dimensions,
        h: dashboard.sections[field].dimensions.h,
        minH: dashboard.sections[field].dimensions.minH,
      },
    },
  });

  /* reset panel to it's initial state - no data into blocks and the default height for the panel with empty blocks */
  resetPanelHeights = () => {
    // eslint-disable-next-line react/no-access-state-in-setstate
    const reset = Object.assign({}, ...Object.keys(this.state.dashboard).map(k => this.resetPanelHeight(k)));
    this.setState({
      // eslint-disable-next-line react/no-access-state-in-setstate
      ...this.state,
      dashboard: reset,
    });
  };

  bootPanels = () => {
    this.panelsLoaded = 0;
    this.panelsBooted = 'booting';
    this.panelState.dashboard = { ...this.state.dashboard };
    this.resetPanelHeights();
    map(this.state.load, panel => this.bootPanel(panel));
  };

  bootPanel = panel => {
    // Count the number of the blocks
    let blocksLoaded = 0;
    let newHeight = 0;
    const array = this.state.dashboard[panel].items;
    const filterParams = buildFilterParams(this.props.filterParams);
    let filterList = `${array[0].i}`;
    for (let j = 1; j < array.length; j += 1) {
      filterList += `,${array[j].i}`;
    }
    axios
      .get(`${config.API_URL + config.ES_BASE_PATH}fields_stats/?fields=${filterList}&${filterParams}&page_size=5${this.qFilter}`)
      .then(jsonResponse => {
        const gjson = jsonResponse;
        // Validation of the data property
        if (typeof gjson.data === 'undefined' || gjson.data === null) {
          gjson.data = [];
        }

        for (let j = 0; j < array.length; j += 1) {
          const block = array[j];
          const json = block.i in gjson.data ? gjson.data[block.i] : [];
          // When all of the blocks from a single panel are loaded, then mark the panel as loaded
          blocksLoaded += 1;
          if (blocksLoaded === this.state.dashboard[panel].items.length) {
            this.panelsLoaded += 1;
          }

          const height = Math.ceil((json.length * dashboard.block.defaultItemHeight + dashboard.block.defaultHeadHeight) / 13);
          const panelHeight = json.length
            ? 10 + json.length * dashboard.block.defaultItemHeight + dashboard.block.defaultHeadHeight + dashboard.panel.defaultHeadHeight
            : dashboard.panel.defaultHeadHeight;
          const isPanelLoaded = !this.state.dashboard[panel].items.find(itm => itm.data !== null && itm.data.length === 0);

          const items = this.panelState.dashboard[panel].items.map(el => {
            if (el.i === block.i) {
              const data = json.length ? json : [];

              if (data) {
                for (let idx = 0; idx < data.length; idx += 1) {
                  if (!data[idx].key) {
                    data[idx].key = 'Unknown';
                  }
                }
              }

              let extended = {
                dimensions: {
                  ...el.dimensions,
                  lg: {
                    ...el.dimensions.lg,
                    ...this.getBlockFromLS(panel, block.i, 'lg'),
                    maxH: height,
                    minH: height,
                    h: height,
                  },
                  md: {
                    ...el.dimensions.md,
                    ...this.getBlockFromLS(panel, block.i, 'md'),
                    maxH: height,
                    minH: height,
                    h: height,
                  },
                  sm: {
                    ...el.dimensions.sm,
                    ...this.getBlockFromLS(panel, block.i, 'sm'),
                    maxH: height,
                    minH: height,
                    h: height,
                  },
                  xs: {
                    ...el.dimensions.xs,
                    ...this.getBlockFromLS(panel, block.i, 'xs'),
                    maxH: height,
                    minH: height,
                    h: height,
                  },
                },
              };
              if (el.i === block.i) {
                extended = { ...extended, data };
              }
              return Object.assign({}, el, extended);
            }
            return el;
          });

          newHeight = newHeight < panelHeight ? panelHeight : newHeight;
          this.panelState = {
            dashboard: {
              ...this.panelState.dashboard,
              [panel]: {
                ...this.panelState.dashboard[panel],
                loaded: isPanelLoaded,
                dimensions: {
                  ...this.panelState.dashboard[panel].dimensions,
                  h: newHeight,
                  minH: newHeight,
                },
                items,
              },
            },
          };

          // When all of the panels are loaded then hit the floor just once
          if (this.panelsLoaded === this.state.load.length) {
            this.panelsAdjusted = false;
            if (this.panelsBooted !== 'yes') {
              this.panelsBooted = 'yes';
            }
            this.setState({
              // eslint-disable-next-line react/no-access-state-in-setstate
              ...this.state,
              ...this.panelState,
            });
          }
        }
      })
      .catch(() => {
        this.setState({
          // eslint-disable-next-line react/no-access-state-in-setstate
          ...this.state,
          dashboard: {
            // eslint-disable-next-line react/no-access-state-in-setstate
            ...this.state.dashboard,
            ...this.resetPanelHeight(panel, []),
          },
        });
        this.panelsBooted = 'yes';
      });
  };

  itemCopyModeOnClick = (event, itemPath, key, parentElem) => {
    if (event.ctrlKey) {
      this.setState({ copiedItem: itemPath });
      setTimeout(() => {
        this.setState({ copiedItem: '' });
      }, 1500);
      copyTextToClipboard(key, parentElem);
    }
  };

  onMouseMove = (event, itemPath) => {
    if (this.state.hoveredItem !== itemPath) {
      this.setState({ hoveredItem: itemPath });
    }
    if (this.state.copyMode !== event.ctrlKey) {
      this.setState({ copyMode: event.ctrlKey });
    }
  };

  onMouseLeave = (event, itemPath) => {
    if (this.state.hoveredItem === itemPath) {
      this.setState({ hoveredItem: null });
    }
  };

  createElement = block => {
    const filterParams = buildFilterParams(this.props.filterParams);
    const url = `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${block.i}&${filterParams}&page_size=30${this.qFilter}`;
    const menu = (
      <Menu>
        <Menu.Item key="load-more" onClick={() => this.loadMore(block, url)} data-toggle="modal">
          Load more results
        </Menu.Item>
        <Menu.Item key="download-data" onClick={() => this.download(url, block.title)} data-toggle="modal">
          Download
        </Menu.Item>
      </Menu>
    );
    return (
      <UICard
        key={block.i}
        title={
          <div
            className={`hunt-stat-title ${this.state.editMode ? 'dashboard-editable-mode' : ''}`}
            data-toggle="tooltip"
            title={block.title}
            style={{ display: 'grid', gridTemplateColumns: '1fr min-content' }}
          >
            <div>{block.title}</div>
            <div>
              {block.data === null && <Spin size="small" />}
              {block.data !== null && block.data.length > 0 && (
                <Dropdown overlay={menu} trigger={['click']}>
                  <a className="ant-dropdown-link" style={{ color: COLOR_BRAND_BLUE }} onClick={e => e.preventDefault()}>
                    <MenuOutlined />
                  </a>
                </Dropdown>
              )}
            </div>
          </div>
        }
        headStyle={{ color: COLOR_BRAND_BLUE, textAlign: 'center' }}
        style={{ overflow: 'hidden' }}
      >
        {block.data !== null &&
          block.data.map(item => (
            <EventValue
              key={item.key}
              field={block.i}
              value={item.key}
              format={block.format}
              copyMode={this.state.copyMode}
              right_info={<>{item.doc_count}</>}
              hasCopyShortcut
            />
          ))}
        {block.data !== null && block.data.length === 0 && <Empty style={{ margin: 0 }} image={Empty.PRESENTED_IMAGE_SIMPLE} />}
      </UICard>
    );
  };

  getMacroLayouts = () =>
    this.state.load.map(panel => ({
      ...this.state.dashboard[panel].dimensions,
      isDraggable: this.state.editMode,
      i: panel.toString(),
    }));

  getMicroLayouts = (panel, bp) => {
    const tallestBlock = this.makeHeightsEqual(panel, bp);
    return this.state.dashboard[panel].items.map(item => ({
      ...item.dimensions[bp],
      h: tallestBlock,
      maxH: tallestBlock,
      minH: tallestBlock,
      i: item.i.toString(),
    }));
  };

  makeHeightsEqual = (panel, bp) => {
    let h = 0;
    const blocks = this.state.dashboard[panel].items;
    for (let i = 0; i < blocks.length; i += 1) {
      h = h > blocks[i].dimensions[bp].h ? h : blocks[i].dimensions[bp].h;
    }
    return h;
  };

  resetDashboard = e => {
    e.preventDefault();
    // eslint-disable-next-line no-alert
    const ask = window.confirm('Confirm reset positions of the dashboard panels?');
    if (ask) {
      store.remove('dashboardMacroLayout');
      store.remove('dashboardMicroLayout');
      window.location.reload();
    }
  };

  switchEditMode = e => {
    // eslint-disable-next-line react/no-access-state-in-setstate
    this.setState({ editMode: !this.state.editMode });
    e.preventDefault();
  };

  adjustPanelsHeight = (p = null) => {
    let panelsArray = [];

    if (p === null) {
      panelsArray = this.state.load;
    } else {
      panelsArray.push(p);
    }

    let tmpState = this.state;
    let stateChanged = false;
    for (let i = 0; i < panelsArray.length; i += 1) {
      const panelBodySize = this.getPanelBodySize(panelsArray[i]);
      const panelRealSize = parseInt(panelBodySize, 10) + parseInt(dashboard.panel.defaultHeadHeight, 10);
      if (this.getPanelSize(panelsArray[i]) !== panelRealSize) {
        stateChanged = true;
        tmpState = {
          ...tmpState,
          dashboard: {
            ...tmpState.dashboard,
            [panelsArray[i]]: {
              ...tmpState.dashboard[panelsArray[i]],
              dimensions: {
                ...tmpState.dashboard[panelsArray[i]].dimensions,
                h: panelRealSize,
                minH: panelRealSize,
              },
            },
          },
        };
      }
    }
    if (stateChanged) {
      this.setState(tmpState);
    }
  };

  getPanelSize = panel => parseInt(document.querySelector(`#panel-${panel}`).style.height.replace('px', ''), 10);

  getPanelBodySize = panel => parseInt(document.querySelector(`#panel-${panel} div.react-grid-layout`).style.height.replace('px', ''), 10);

  onChangeMacroLayout = macroLayout => {
    store.set('dashboardMacroLayout', macroLayout);
    let { dashboard: tmpState } = this.state;
    for (let k = 0; k < macroLayout.length; k += 1) {
      tmpState = {
        ...tmpState,
        [macroLayout[k].i]: {
          ...tmpState[macroLayout[k].i],
          dimensions: macroLayout[k],
        },
      };
    }
    this.setState({ dashboard: tmpState });
  };

  onDragStartMicro = () => {
    this.panelAutoresize = true;
  };

  onResizeStartMicro = () => {
    this.panelAutoresize = true;
  };

  onChangeMicroLayout = (panel, microLayout) => {
    if (this.panelAutoresize) {
      if (this.state.breakPoint !== null) {
        const ls = store.get('dashboardMicroLayout') || {
          [panel]: {
            lg: {},
            md: {},
            sm: {},
            xs: {},
          },
        };
        store.set('dashboardMicroLayout', {
          ...ls,
          [panel]: {
            ...ls[panel],
            [this.state.breakPoint]: microLayout,
          },
        });

        let obj = this.state;
        for (let j = 0; j < microLayout.length; j += 1) {
          obj = {
            ...obj,
            dashboard: {
              ...this.state.dashboard,
              [panel]: {
                ...this.state.dashboard[panel],
                items: this.state.dashboard[panel].items.map(vv => {
                  const innerItem = { ...vv };
                  if (microLayout[j].i === vv.i) {
                    innerItem.dimensions[this.state.breakPoint] = microLayout[j];
                  }
                  return Object.assign({}, vv, innerItem);
                }),
              },
            },
          };
        }

        this.setState(obj);
      }
      this.adjustPanelsHeight(panel);
      this.panelAutoresize = false;
    } else if (this.breakPointChanged) {
      // Block any further redundant calls
      this.breakPointChanged = false;
      // Execute it with a little delay in order to be sure that the animation will be finished
      setTimeout(() => {
        this.adjustPanelsHeight();
      }, 500);
    }
  };

  onBreakPointChange = breakpoint => {
    if (this.state.breakPoint !== breakpoint) {
      this.breakPointChanged = true;
      this.setState({ breakPoint: breakpoint });
    }
  };

  loadMore = (item, url) => {
    axios.get(url).then(json => {
      const data = json.data.length ? json.data : null;

      if (data) {
        for (let idx = 0; idx < data.length; idx += 1) {
          if (!data[idx].key) {
            data[idx].key = 'Unknown';
          }
        }
      }

      this.setState({ moreModal: item, moreResults: json.data });
    });
  };

  download = (url, fileName) => {
    const name = fileName.toLowerCase();
    message.success(`Downloading ${name}`);
    axios.get(url).then(json => {
      downloadData.text(json.data.map(o => o.key).join('\n'), name);
    });
  };

  // eslint-disable-next-line react/no-access-state-in-setstate
  hideMoreModal = () => this.setState({ ...this.state, moreModal: null });

  onChangeChartTarget = chartTarget => {
    this.setState({
      chartTarget,
    });

    store.set('chartTarget', chartTarget);
  };

  menu = (
    <Menu>
      <Menu.Item onClick={() => this.onChangeChartTarget(!this.state.chartTarget)} data-toggle="modal">
        Switch timeline by probes/tags
      </Menu.Item>
    </Menu>
  );

  render() {
    return (
      <div>
        <Helmet>
          <title>{`${STAMUS} - Dashboards`}</title>
        </Helmet>

        <ErrorHandler>
          <Filters page="DASHBOARDS" section={sections.GLOBAL} queryTypes={['filter', 'filter_host_id']} filterTypes={['filter']} />
        </ErrorHandler>

        <Row style={{ marginTop: 10 }}>
          <Col lg={20} md={18} sm={24} xs={24} style={{ paddingRight: '0px' }}>
            <HuntTimeline
              style={{ marginTop: '15px' }}
              filterParams={this.props.filterParams}
              chartTarget={this.state.chartTarget}
              filters={this.props.filtersWithAlert}
              systemSettings={this.props.systemSettings}
            />
          </Col>
          <Col lg={4} md={6} sm={24} xs={24} style={{ paddingLeft: '0px' }}>
            <HuntTrend filterParams={this.props.filterParams} filters={this.props.filtersWithAlert} systemSettings={this.props.systemSettings} />
            {typeof this.state.chartTarget !== 'undefined' && (process.env.REACT_APP_HAS_TAG === '1' || process.env.NODE_ENV === 'development') && (
              <div style={{ position: 'absolute', zIndex: 10, top: 0, right: '30px' }}>
                <Dropdown id="more-actions" overlay={this.menu} trigger={['click']}>
                  <a className="ant-dropdown-link" onClick={e => e.preventDefault()}>
                    <MenuOutlined />
                  </a>
                </Dropdown>
              </div>
            )}
          </Col>
        </Row>
        <div className="drag-and-drop-container">
          <Row>
            <Col style={{ marginLeft: 'auto' }}>
              <a href="#edit" onClick={this.switchEditMode}>
                {this.state.editMode ? 'switch off edit mode' : 'edit'}
              </a>
              <span> • </span> {/* ignore_utf8_check: 8226 */}
              <a href="#reset" onClick={this.resetDashboard}>
                reset
              </a>
            </Col>
          </Row>
          <div className="clearfix" />

          {this.panelsBooted !== 'no' && (
            <ResponsiveReactGridLayout
              margin={[0, 0.01]}
              compactType="vertical"
              isResizable={false}
              rowHeight={1}
              draggableHandle=".hunt-row-title"
              cols={{
                lg: 1,
                md: 1,
                sm: 1,
                xs: 1,
                xxs: 1,
              }}
              layouts={{
                lg: this.getMacroLayouts(),
                md: this.getMacroLayouts(),
                sm: this.getMacroLayouts(),
                xs: this.getMacroLayouts(),
              }}
              onLayoutChange={this.onChangeMacroLayout}
            >
              {this.panelsBooted !== 'no' &&
                this.state.load.map(panel => (
                  <div key={panel} id={`panel-${panel}`}>
                    <h2 className={`hunt-row-title ${this.state.editMode ? 'dashboard-editable-mode' : ''}`}>{this.state.dashboard[panel].title}</h2>
                    <ResponsiveReactGridLayout
                      margin={[5, 5]}
                      compactType="vertical"
                      layouts={{
                        lg: this.getMicroLayouts(panel, 'lg'),
                        md: this.getMicroLayouts(panel, 'md'),
                        sm: this.getMicroLayouts(panel, 'sm'),
                        xs: this.getMicroLayouts(panel, 'xs'),
                      }}
                      onDragStart={this.onDragStartMicro}
                      onBreakpointChange={(breakPoint, cols) => this.onBreakPointChange(breakPoint, cols, panel)}
                      onLayoutChange={e => this.onChangeMicroLayout(panel, e)}
                      onResizeStart={this.onResizeStartMicro}
                      isDraggable={this.state.editMode}
                      isResizable={this.state.editMode}
                      resizeHandles={this.state.editMode ? ['se'] : []}
                      rowHeight={10}
                      draggableHandle=".hunt-stat-title"
                      cols={{
                        lg: 32,
                        md: 24,
                        sm: 16,
                        xs: 8,
                        xxs: 4,
                      }}
                    >
                      {this.state.dashboard[panel].items.map(block => this.createElement(block))}
                    </ResponsiveReactGridLayout>
                  </div>
                ))}
            </ResponsiveReactGridLayout>
          )}
        </div>
        <Modal
          title="More results"
          footer={null}
          visible={!(this.state.moreModal === null)}
          onCancel={() => {
            this.hideMoreModal();
          }}
        >
          <div id="more-result-modal">
            {this.state.moreModal &&
              this.state.moreResults.map(item => (
                <ErrorHandler key={item.key}>
                  <EventValue
                    field={this.state.moreModal.i}
                    value={item.key}
                    right_info={<span className="badge">{item.doc_count}</span>}
                    copyMode={this.state.copyMode}
                    hasCopyShortcut
                  />
                </ErrorHandler>
              ))}
          </div>
        </Modal>
      </div>
    );
  }
}

HuntDashboard.propTypes = {
  systemSettings: PropTypes.any,
  filters: PropTypes.any,
  filtersWithAlert: PropTypes.array,
  filterParams: PropTypes.object.isRequired,
  user: PropTypes.shape({
    pk: PropTypes.any,
    timezone: PropTypes.any,
    username: PropTypes.any,
    firstName: PropTypes.any,
    lastName: PropTypes.any,
    isActive: PropTypes.any,
    email: PropTypes.any,
    dateJoined: PropTypes.any,
    permissions: PropTypes.any,
  }),
};

const mapStateToProps = createStructuredSelector({
  filters: makeSelectGlobalFilters(),
  filtersWithAlert: makeSelectGlobalFilters(true),
  alertTag: makeSelectAlertTag(),
  filterParams: makeSelectFilterParams(),
  systemSettings: globalSelectors.makeSelectSystemSettings(),
});

const withConnect = connect(mapStateToProps);
export default compose(withPermissions, withConnect)(HuntDashboard);
