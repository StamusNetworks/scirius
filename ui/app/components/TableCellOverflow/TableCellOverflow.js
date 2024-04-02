import React from 'react';

import { Popover } from 'antd';
import PropTypes from 'prop-types';

import * as Style from './style';

export const TableCellOverflow = ({ value, title, component }) => {
  const Component = component;

  return (
    <Style.LimitedCell
      onClick={e => {
        e.preventDefault();
        e.stopPropagation();
      }}
    >
      <Style.ValueContainer>
        {value.slice(0, 1).map(v => (
          <Component key={v} value={v} />
        ))}
      </Style.ValueContainer>
      {value.length > 1 && (
        <Popover
          title={title}
          content={
            <Style.PopoverContent>
              <ol>
                {value.slice(1).map(v => (
                  <li key={v}>
                    <Component value={v} />
                  </li>
                ))}
              </ol>
            </Style.PopoverContent>
          }
        >
          <Style.More>({value.length - 1} more)</Style.More>
        </Popover>
      )}
    </Style.LimitedCell>
  );
};

TableCellOverflow.propTypes = {
  value: PropTypes.array.isRequired,
  title: PropTypes.string,
  component: PropTypes.elementType.isRequired,
};
