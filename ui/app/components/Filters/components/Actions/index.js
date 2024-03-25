import React from 'react';

import PropTypes from 'prop-types';
import { useDispatch, useSelector } from 'react-redux';
import styled from 'styled-components';

import strGlobalActions from 'ui/containers/App/actions';
import * as huntGlobalStore from 'ui/containers/HuntApp/stores/global';
import { useStore } from 'ui/mobx/RootStoreProvider';
import ruleSetsActions from 'ui/stores/filters/actions';
import ruleSetsSelectors from 'ui/stores/filters/selectors';

import Title from '../../Title.styled';
import ActionsButtons from '../ActionsButtons';
import ClearFiltersButton from '../ClearFiltersButton';
import LoadFilterSetButton from '../LoadFilterSetButton';
import SaveFilterSetButton from '../SaveFilterSetButton';

const ActionsContainer = styled.div`
  display: flex;
  flex-direction: column;
`;

const Actions = ({ section }) => {
  const { commonStore } = useStore();
  const dispatch = useDispatch();
  const supportedActions = useSelector(ruleSetsSelectors.makeSelectSupportedActions());
  return (
    <div>
      <Title>Actions</Title>
      <ActionsContainer>
        <ClearFiltersButton
          onClick={() => {
            dispatch(huntGlobalStore.clearFilters(section));
            commonStore.clearFilters();
          }}
        />
        <LoadFilterSetButton onClick={() => dispatch(strGlobalActions.setFilterSets(true))} />
        <SaveFilterSetButton onClick={() => dispatch(ruleSetsActions.saveFiltersModal(true))} />
        <ActionsButtons supportedActions={supportedActions} />
      </ActionsContainer>
    </div>
  );
};

export default Actions;

Actions.propTypes = {
  section: PropTypes.string.isRequired,
};
