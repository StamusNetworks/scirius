import React, { useState } from 'react';

import { ZoomInOutlined, ZoomOutOutlined } from '@ant-design/icons';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import TypedValue from 'ui/components/TypedValue';
import options from 'ui/components/TypedValue/options';
import { COLOR_BOX_HEADER } from 'ui/constants/colors';
import { useStore } from 'ui/mobx/RootStoreProvider';
import Filter from 'ui/utils/Filter';

const Container = styled.div`
  display: grid;
  gap: 1rem;
  grid-template-columns: 1fr min-content;
  align-items: center;
  width: 100%;
  background: ${p => (p.hover ? '#f0f2f5' : 'none')};
`;

export const Count = styled.span`
  background: ${COLOR_BOX_HEADER};
  color: #fff;
  padding: 0 5px;
  font-size: 12px;
  cursor: default;
`;

const EventValue = ({ filter, count, copyMode }) => {
  const [hover, setHover] = useState(false);
  const { commonStore } = useStore();

  const additionalLinks = [
    {
      key: 'eventValue1',
      label: (
        <div data-test="filter-on-value" onClick={() => commonStore.addFilter(filter)}>
          <ZoomInOutlined /> <span>Filter on value</span>
        </div>
      ),
    }, // Filter on value
    {
      key: 'eventValue2',
      label: (
        <div
          data-test="negated-filter-on-value"
          onClick={() => {
            filter.negated = true;
            commonStore.addFilter(filter);
          }}
        >
          <ZoomOutOutlined /> <span>Negated filter on value</span>
        </div>
      ),
    }, // Negated filter on value
    options.COPY_TO_CLIPBOARD(filter.displayValue),
  ];

  return (
    <Container data-test="event-value" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)} hover={hover}>
      <TypedValue filter={filter} additionalLinks={additionalLinks} />
      {count && !(copyMode && hover) && <Count>{count}</Count>}
    </Container>
  );
};

EventValue.propTypes = {
  filter: PropTypes.instanceOf(Filter),
  count: PropTypes.number,
  copyMode: PropTypes.bool,
};

export default EventValue;
