import React, { useEffect, useState } from 'react';
import { Dropdown, Menu } from 'antd';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import PropTypes from 'prop-types';
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

const OptionHandler = styled.a`
  display: flex;
  flex: 1;
`;

const HandlerContainer = styled.a`
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

  useEffect(() => {
    onChange(option?.id, direction);
  }, [option?.id, direction]);

  return (
    <Container>
      <OptionContainer>
        <Dropdown
          overlay={
            <Menu>
              {options
                .filter(o => o.page === page)
                .map(o => (
                  <Menu.Item icon={o.icon}>
                    <a onClick={() => setOption(o)}>{o.title}</a>
                  </Menu.Item>
                ))}
            </Menu>
          }
        >
          <OptionHandler onClick={e => e.preventDefault()}>
            {option && (
              <HandlerContainer>
                {React.cloneElement(option.icon, iconSelectedProps)} <Value>{option.title}</Value>
              </HandlerContainer>
            )}
            {!option && <Placeholder>Sort</Placeholder>}
          </OptionHandler>
        </Dropdown>
      </OptionContainer>
      <DirectionContainer>
        <Dropdown
          overlay={
            <Menu>
              <Menu.Item icon={<ArrowUpOutlined />}>
                <a
                  onClick={() => {
                    setDirection('asc');
                  }}
                >
                  Ascending
                </a>
              </Menu.Item>
              <Menu.Item icon={<ArrowDownOutlined />}>
                <a
                  onClick={() => {
                    setDirection('desc');
                  }}
                >
                  Descending
                </a>
              </Menu.Item>
            </Menu>
          }
        >
          <a onClick={e => e.preventDefault()}>{direction === 'asc' ? <ArrowUpOutlined /> : <ArrowDownOutlined />}</a>
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
