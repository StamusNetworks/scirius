import React, { useRef } from 'react';
import styled from 'styled-components';
import PropTypes from 'prop-types';
import { Popover } from 'antd';

const Cell = styled.div`
  overflow: hidden;
  max-width: ${p => p.width || 170}px;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: flex;
  gap: 5px;
  flex-direction: ${p => (p.direction === 'column' ? 'column' : 'row')};
`;

const Content = styled.div``;

const TableCellOverflow = ({ title, content, width, direction, children }) => {
  const ref = useRef();
  return (
    <div onClick={e => e.stopPropagation()}>
      <Popover {...(title ? { title } : null)} content={<Content>{content || children}</Content>} trigger="hover">
        <Cell ref={ref} $width={width} $direction={direction}>
          {children}
        </Cell>
      </Popover>
    </div>
  );
};
export default TableCellOverflow;

TableCellOverflow.propTypes = {
  title: PropTypes.string,
  width: PropTypes.number,
  direction: PropTypes.oneOf(['row', 'column']),
  content: PropTypes.any,
  children: PropTypes.any.isRequired,
};
