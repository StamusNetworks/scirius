import React, { useState } from 'react';
import PropTypes from 'prop-types';
import TypedValue from 'ui/components/TypedValue';
import styled from 'styled-components';
import { COLOR_BOX_HEADER } from 'ui/constants/colors';
import Filter from 'ui/utils/Filter';

const Container = styled.div`
  display: grid;
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

  return (
    <Container data-test="event-value" onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)} hover={hover}>
      <TypedValue filter={filter} />
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
