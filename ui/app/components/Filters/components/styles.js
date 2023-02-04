import styled from 'styled-components';

export const ActionButton = styled.div`
  display: flex;
  flex-direction: row;
  align-items: center;
  cursor: ${p => (p.active ? 'pointer' : 'default')};
  border-radius: 5px;
  gap: 2px;
  &:hover {
    background: ${p => (p.active ? '#f0f2f5' : 'none')};
  }
  svg {
    padding: 0 2px;
    fill: ${p => (p.active ? '#196d9e' : '#000')};
  }
`;
