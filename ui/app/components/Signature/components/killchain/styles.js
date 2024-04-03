import styled from 'styled-components';

const height = '16px';
const arrow = '8px';

export const Shape = styled.div`
  width: 16px;
  height: ${height};
  position: relative;
  background: ${({ active }) => (active ? 'red' : 'lightgray')};
  border-left-color: ${({ active }) => (active ? 'red' : 'lightgray')};
  margin-right: ${arrow};

  display: flex;
  align-items: center;
  justify-content: center;
  cursor: default;

  &:after {
    content: '';
    position: absolute;
    left: 0;
    bottom: 0;
    width: 0;
    height: 0;
    border-left: calc(${arrow} * 1.5) solid white;
    border-top: calc(${height} / 2) solid transparent;
    border-bottom: calc(${height} / 2) solid transparent;
  }

  &:before {
    content: '';
    position: absolute;
    right: calc(${arrow} * -1.5);
    bottom: 0;
    width: 0;
    height: 0;
    border-left: calc(${arrow} * 1.5) solid ${({ active }) => (active ? 'red' : 'lightgray')};
    border-top: calc(${height} / 2) solid transparent;
    border-bottom: calc(${height} / 2) solid transparent;
  }
`;

export const Killchain = styled.div`
  display: flex;
  flex-direction: column;
`;

export const KCGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(7, 1fr);
`;

export const KCTitle = styled.p`
  margin: 0;
  text-align: center;
`;
