/* eslint-disable react/no-access-state-in-setstate */
import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import { Dropdown, Menu } from 'antd';
import { MenuOutlined } from '@ant-design/icons';
import { createStructuredSelector } from 'reselect';
import { withStore } from 'ui/mobx/RootStoreProvider';
import { sections } from 'ui/constants';
import { compose } from 'redux';
import FilterToggleModal from 'ui/FilterToggleModal';
import ErrorHandler from 'ui/components/Error';
import FilterSetSaveModal from 'ui/components/FilterSetSaveModal';
import filterSetActions from 'ui/stores/filterset/actions';
import { addFilter, generateAlert, setTag, clearFilters, makeSelectAlertTag } from 'ui/containers/HuntApp/stores/global';
import Filter from 'ui/utils/Filter';

class FilterEditKebab extends React.Component {
  constructor(props) {
    super(props);
    this.displayToggle = this.displayToggle.bind(this);
    this.hideToggle = this.hideToggle.bind(this);
    this.state = {
      toggle: { show: false, action: 'delete' },
      filterSets: { showModal: false, page: '', shared: false, name: '' },
    };
    this.closeAction = this.closeAction.bind(this);
    this.convertActionToFilters = this.convertActionToFilters.bind(this);
    this.saveActionToFilterSet = this.saveActionToFilterSet.bind(this);
    this.handleFieldChange = this.handleFieldChange.bind(this);
    this.handleComboChange = this.handleComboChange.bind(this);
    this.handleDescriptionChange = this.handleDescriptionChange.bind(this);
    this.setSharedFilter = this.setSharedFilter.bind(this);
  }

  setSharedFilter(e) {
    this.setState({
      filterSets: {
        showModal: true,
        shared: e.target.checked,
        page: this.state.filterSets.page,
        name: this.state.filterSets.name,
        description: this.state.filterSets.description,
      },
    });
  }

  closeActionToFilterSet = () => {
    this.setState({ filterSets: { showModal: false, shared: false, page: 'DASHBOARDS', name: '', errors: undefined, description: '' } });
  };

  generateAlertTag = () => {
    const { action } = this.props.data;
    return process.env.REACT_APP_HAS_TAG === '1' && (action === 'tag' || action === 'tagkeep')
      ? generateAlert(true, true, true, true, true)
      : this.props.alertTag;
  };

  generateFilterSet = () => {
    const filters = [];
    for (let idx = 0; idx < this.props.data.filter_defs.length; idx += 1) {
      const val = Number(this.props.data.filter_defs[idx].value)
        ? Number(this.props.data.filter_defs[idx].value)
        : this.props.data.filter_defs[idx].value;
      const filter = new Filter(this.props.data.filter_defs[idx].key, val, {
        negated: this.props.data.filter_defs[idx].operator !== 'equal',
        fullString: this.props.data.filter_defs[idx].full_string,
      });
      filters.push({
        id: filter.id,
        key: filter.id,
        label: filter.label,
        value: filter.value,
        negated: filter.negated,
        fullString: filter.fullString,
      });
    }
    return filters;
  };

  displayToggle(action) {
    this.setState({ toggle: { show: true, action } });
    this.props.setExpand(false);
  }

  hideToggle() {
    this.setState({ toggle: { show: false, action: this.state.toggle.action } });
    this.props.setExpand(true);
  }

  closeAction() {
    this.setState({ toggle: { show: false, action: 'delete' } });
    this.props.setExpand(true);
  }

  saveActionToFilterSet() {
    this.setState({ filterSets: { showModal: true, page: 'DASHBOARDS', shared: false, name: '', description: '' } });
    this.props.setExpand(false);
  }

  convertActionToFilters() {
    this.props.clearFilters(sections.GLOBAL);
    this.props.store.commonStore.addFilter(this.generateFilterSet());
    if (process.env.REACT_APP_HAS_TAG === '1') {
      this.props.setTag(this.generateAlertTag());
    }
    this.props.history.push(`/stamus/hunting/dashboards/${window.location.search}`);
  }

  handleComboChange(value) {
    this.setState({
      filterSets: {
        showModal: true,
        shared: this.state.filterSets.shared,
        page: value,
        name: this.state.filterSets.name,
        description: this.state.filterSets.description,
      },
    });
  }

  handleFieldChange(event) {
    this.setState({
      filterSets: {
        showModal: true,
        shared: this.state.filterSets.shared,
        page: this.state.filterSets.page,
        name: event.target.value,
        description: this.state.filterSets.description,
      },
    });
  }

  handleDescriptionChange(event) {
    this.setState({
      filterSets: {
        showModal: true,
        shared: this.state.filterSets.shared,
        page: this.state.filterSets.page,
        name: this.state.filterSets.name,
        description: event.target.value,
      },
    });
  }

  render() {
    return (
      <React.Fragment>
        {this.state.filterSets.showModal && (
          <FilterSetSaveModal title="Create new Filter Set From Action" close={this.closeActionToFilterSet} content={this.generateFilterSet()} />
        )}
        <Dropdown
          id="filterActions"
          overlay={
            <Menu onClick={({ domEvent }) => domEvent.stopPropagation()}>
              {this.props.store.commonStore.user?.isActive && this.props.store.commonStore.user?.permissions.includes('rules.events_edit') && (
                <React.Fragment>
                  {this.props.data.index !== 0 && (
                    <Menu.Item
                      key="1"
                      data-test="send-action-to-top"
                      onClick={() => {
                        this.displayToggle('movetop');
                      }}
                    >
                      Send Action to top
                    </Menu.Item>
                  )}
                  <Menu.Item
                    key="2"
                    data-test="move-action"
                    onClick={() => {
                      this.displayToggle('move');
                    }}
                  >
                    Move Action
                  </Menu.Item>
                  <Menu.Item
                    key="3"
                    data-test="send-action-to-bottom"
                    onClick={() => {
                      this.displayToggle('movebottom');
                    }}
                  >
                    Send Action to bottom
                  </Menu.Item>
                  <Menu.Item
                    key="4"
                    data-test="delete-action"
                    onClick={() => {
                      this.displayToggle('delete');
                    }}
                  >
                    Delete Action
                  </Menu.Item>
                </React.Fragment>
              )}

              <Menu.Item
                key="5"
                data-test="convert-action-to-filters"
                onClick={() => {
                  this.convertActionToFilters();
                }}
              >
                Convert Action to Filters
              </Menu.Item>
              {this.props.store.commonStore.user?.isActive && (
                <Menu.Item
                  key="6"
                  data-test="save-action-as-filter-set"
                  onClick={() => {
                    this.saveActionToFilterSet();
                  }}
                >
                  Save Action as Filter set
                </Menu.Item>
              )}
            </Menu>
          }
          trigger={['click']}
        >
          <a
            className="ant-dropdown-link"
            data-test={`kebab-dropdown-${this.props.data.index}`}
            onClick={e => {
              e.preventDefault();
              e.stopPropagation();
            }}
          >
            <MenuOutlined />
          </a>
        </Dropdown>
        <ErrorHandler>
          <FilterToggleModal
            show={this.state.toggle.show}
            action={this.state.toggle.action}
            data={this.props.data}
            close={this.closeAction}
            last_index={this.props.last_index}
            needUpdate={this.props.needUpdate}
          />
        </ErrorHandler>
      </React.Fragment>
    );
  }
}
FilterEditKebab.propTypes = {
  data: PropTypes.any,
  last_index: PropTypes.any,
  needUpdate: PropTypes.any,
  addFilter: PropTypes.any,
  setTag: PropTypes.func,
  clearFilters: PropTypes.func,
  alertTag: PropTypes.object,
  setExpand: PropTypes.func,
  history: PropTypes.object,
  store: PropTypes.object,
};

const mapStateToProps = createStructuredSelector({
  alertTag: makeSelectAlertTag(),
});

const mapDispatchToProps = {
  loadFilterSetsRequest: filterSetActions.loadFilterSetsRequest,
  addFilter,
  clearFilters,
  setTag,
};

const withConnect = connect(mapStateToProps, mapDispatchToProps);
export default compose(withRouter, withConnect)(withStore(FilterEditKebab));
