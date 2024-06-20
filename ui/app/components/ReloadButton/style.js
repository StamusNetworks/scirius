import styled from 'styled-components';

export const ReloadButton = styled.div`
  display: flex;
  align-items: center;

  background: transparent;
  border: none;
  color: rgba(255, 255, 255);
  opacity: 0.65;

  padding: 0 20px;
  gap: 8px;

  svg {
    width: 24px;
    height: 24px;
  }

  &:hover {
    color: rgba(255, 255, 255);
    opacity: 1;
  }
`;
