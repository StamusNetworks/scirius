import React, { useEffect, useState, useRef } from 'react';

import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';
import { Dropdown, Menu } from 'antd';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import options from 'ui/components/Sort/options';

const iconSelectedProps = {
  style: {
    background: 'rgb(0, 87, 146)',
    color: '#FFFFFF',
    padding: '3px 5px',
    borderRadius: '5px 0px 0px 5px',
    fontSize: '14px',
    alignSelf: 'stretch',
  },
};

const Container = styled.div`
  display: flex;
  border: 1px solid rgb(0, 87, 146);
  border-radius: 5px;
`;

const OptionContainer = styled.div`
  flex: 4;
  padding-right: 5px;
`;

const OptionHandler = styled.div`
  display: flex;
  flex: 1;
  cursor: default;
`;

const HandlerContainer = styled.div`
  display: flex;
  gap: 5px;
  align-items: center;
`;

const Placeholder = styled.div`
  padding: 0 5px;
`;

const Value = styled.div`
  flex: 1;
`;

const DirectionContainer = styled.div`
  flex: 1;
  padding: 0 3px;
  display: flex;
  align-items: center;
  flex-direction: row;
  justify-content: center;
  border-left: 1px solid rgb(0, 87, 146);
`;

const Sort = ({ page, onChange, value }) => {
  const [option, setOption] = useState(options.find(o => o.id === value.option && o.page === page));
  const [direction, setDirection] = useState(value.direction);

  const mount = useRef(true);
  useEffect(() => {
    if (mount.current) {
      mount.current = false;
      return;
    }
    onChange(option?.id, direction);
  }, [option?.id, direction, mount]);

  return (
    <Container data-test="sort">
      <OptionContainer data-test="sort-by">
        <Dropdown
          overlay={
            <Menu>
              {options
                .filter(o => o.page === page)
                .map((o, i) => (
                  // eslint-disable-next-line react/no-array-index-key
                  <Menu.Item icon={o.icon} key={i} onClick={() => setOption(o)} data-test={`sort-by-${o.title}`}>
                    {o.title}
                  </Menu.Item>
                ))}
            </Menu>
          }
        >
          <OptionHandler onClick={e => e.preventDefault()}>
            {option && (
              <HandlerContainer>
                {React.cloneElement(option.icon, iconSelectedProps)} <Value data-test="sort-selected">{option.title}</Value>
              </HandlerContainer>
            )}
            {!option && <Placeholder>Sort</Placeholder>}
          </OptionHandler>
        </Dropdown>
      </OptionContainer>
      <DirectionContainer data-test="sort-direction">
        <Dropdown
          overlay={
            <Menu>
              <Menu.Item
                data-test="sort-direction-Ascending"
                key="asc"
                icon={<ArrowUpOutlined />}
                onClick={() => {
                  setDirection('asc');
                }}
              >
                Ascending
              </Menu.Item>
              <Menu.Item
                data-test="sort-direction-Descending"
                key="desc"
                icon={<ArrowDownOutlined />}
                onClick={() => {
                  setDirection('desc');
                }}
              >
                Descending
              </Menu.Item>
            </Menu>
          }
        >
          {direction === 'asc' ? (
            <ArrowUpOutlined data-test="sort-selected-direction-asc" />
          ) : (
            <ArrowDownOutlined data-test="sort-selected-direction-desc" />
          )}
        </Dropdown>
      </DirectionContainer>
    </Container>
  );
};

export default React.memo(Sort, function (prevSort, nextSort) {
  return prevSort.page === nextSort.page && prevSort.value.option === nextSort.value.option;
});

Sort.propTypes = {
  page: PropTypes.string,
  onChange: PropTypes.func.isRequired,
  value: PropTypes.shape({
    option: PropTypes.string,
    direction: PropTypes.string,
  }).isRequired,
};
