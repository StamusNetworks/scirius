import React from 'react';
import PropTypes from 'prop-types';
import { PAGE_STATE } from 'constants';
import SignaturesPage from 'ui/containers/SignaturesPage';
import DashboardPage from 'ui/containers/DashboardPage';
import HistoryPage from 'ui/containers/HistoryPage';
import AlertsPage from 'ui/containers/AlertsPage';
import ActionsPage from 'ui/containers/ActionsPage';

const DisplayPage = (props) => {
  let displayedPage = null;
  switch (props.page) {
    case PAGE_STATE.rules_list:
    default:
      displayedPage = (
        <SignaturesPage
          systemSettings={props.systemSettings}
          rules_list={props.rules_list}
          updateListState={props.updateRuleListState}
          page={props.page}
        />
      );
      break;
    case PAGE_STATE.dashboards:
      // FIXME remove or change updateRuleListState
      displayedPage = (
        <DashboardPage
          systemSettings={props.systemSettings}
          rules_list={props.rules_list}
          updateListState={props.updateRuleListState}
          needReload={props.needReload}
          page={props.page}
        />
      );
      break;
    case PAGE_STATE.history:
      displayedPage = (
        <HistoryPage
          systemSettings={props.systemSettings}
          rules_list={props.history_list}
          filters={props.historyFilters}
          updateListState={props.updateHistoryListState}
          switchPage={props.switchPage}
          updateFilterState={props.updateHistoryFilterState}
          page={props.page}
        />
      );
      break;
    case PAGE_STATE.alerts_list:
      displayedPage = (
        <AlertsPage
          systemSettings={props.systemSettings}
          rules_list={props.alerts_list}
          updateListState={props.updateAlertListState}
          page={props.page}
        />
      );
      break;
    case PAGE_STATE.filters_list:
      displayedPage = (
        <ActionsPage
          systemSettings={props.systemSettings}
          rules_list={props.filters_list}
          updateListState={props.updateFilterListState}
          updateFilterState={props.updateFiltersFilterState}
          switchPage={props.switchPage}
        />
      );
      break;
  }

  return displayedPage;
};

DisplayPage.propTypes = {
  page: PropTypes.any,
  systemSettings: PropTypes.any,
  rules_list: PropTypes.any,
  switchPage: PropTypes.any,
  updateRuleListState: PropTypes.any,
  item: PropTypes.any,
  needReload: PropTypes.any,
  history_list: PropTypes.any,
  historyFilters: PropTypes.any,
  updateHistoryListState: PropTypes.any,
  updateHistoryFilterState: PropTypes.any,
  alerts_list: PropTypes.any,
  updateAlertListState: PropTypes.any,
  filters_list: PropTypes.any,
  updateFilterListState: PropTypes.any,
  updateFiltersFilterState: PropTypes.any,
  updateHostListState: PropTypes.any,
};
export default DisplayPage;
