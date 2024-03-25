import React, { useEffect, useRef, useState } from 'react';

import { Popover } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

const LimitedCell = styled.div`
  display: flex;
  flex: 1;
  flex-direction: row;
  justify-content: space-between;
  align-items: flex-start;
`;

const More = styled.div`
  cursor: pointer;
  font-size: 12px;
  padding: 2px 4px;
  border-radius: 5px;
  &:hover {
    background: #005792;
    color: #fff;
  }
`;

const OrderedList = styled.ol`
  margin-bottom: 0;
  & > li {
    padding-left: 10px;
  }
`;

const TableCellOverflow = ({ value, title, component }) => {
  const Component = component;
  const containerRef = useRef(null);
  const [count, setCount] = useState(0);

  useEffect(() => {
    const container = containerRef.current;
    const children = container.childNodes;
    let visible = 0;
    const containerRect = container.getBoundingClientRect();

    Array.from(children).forEach(child => {
      const itemRect = child.getBoundingClientRect();
      if (itemRect.top >= containerRect.top && itemRect.bottom <= containerRect.bottom) {
        visible += 1;
      }
    });

    setCount(visible);
  }, []);

  return (
    <LimitedCell
      onClick={e => {
        e.preventDefault();
        e.stopPropagation();
      }}
    >
      <div ref={containerRef} style={{ display: 'flex', flex: 1, flexDirection: 'row', gap: 8, flexWrap: 'wrap', height: 24, overflow: 'hidden' }}>
        {value.map(v => (
          <Component key={v} value={v} />
        ))}
      </div>
      {value.length - count > 0 && (
        <Popover
          title={title}
          content={
            <div style={{ flex: 1 }}>
              <OrderedList>
                {value.slice(count).map(v => (
                  <li>
                    <Component key={v} value={v} />
                  </li>
                ))}
              </OrderedList>
            </div>
          }
        >
          <More>({value.length - count} more)</More>
        </Popover>
      )}
    </LimitedCell>
  );
};
export default TableCellOverflow;

TableCellOverflow.propTypes = {
  value: PropTypes.array,
  title: PropTypes.string,
  component: PropTypes.object,
};
