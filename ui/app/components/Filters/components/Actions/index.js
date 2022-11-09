import React from 'react';
import styled from 'styled-components';
import { useDispatch, useSelector } from 'react-redux';
import PropTypes from 'prop-types';
import * as huntGlobalStore from 'ui/containers/HuntApp/stores/global';
import strGlobalActions from 'ui/containers/App/actions';
import ruleSetsActions from 'ui/stores/filters/actions';
import ruleSetsSelectors from 'ui/stores/filters/selectors';
import SaveFilterSetButton from '../SaveFilterSetButton';
import LoadFilterSetButton from '../LoadFilterSetButton';
import ClearFiltersButton from '../ClearFiltersButton';
import ActionsButtons from '../ActionsButtons';
import Title from '../../Title.styled';

const ActionsContainer = styled.div`
  display: flex;
  flex-direction: column;
`;

const Actions = ({ section }) => {
  const dispatch = useDispatch();
  const supportedActions = useSelector(ruleSetsSelectors.makeSelectSupportedActions());
  const filters = useSelector(huntGlobalStore.makeSelectGlobalFilters());
  return (
    <div>
      <Title>Actions</Title>
      <ActionsContainer>
        <ClearFiltersButton onClick={() => dispatch(huntGlobalStore.clearFilters(section))} filters={filters} />
        <LoadFilterSetButton onClick={() => dispatch(strGlobalActions.setFilterSets(true))} />
        <SaveFilterSetButton onClick={() => dispatch(ruleSetsActions.saveFiltersModal(true))} filters={filters} />
        <ActionsButtons supportedActions={supportedActions} />
      </ActionsContainer>
    </div>
  );
};

export default Actions;

Actions.propTypes = {
  section: PropTypes.string.isRequired,
};
