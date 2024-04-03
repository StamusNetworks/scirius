import styled from 'styled-components';

export const Row = styled.div`
  display: grid;
  grid-template-columns: ${({ span }) => (span ? '1fr' : '1fr 1fr')};
  gap: 1.5rem;
`;

export const TopRow = styled.div`
  display: grid;
  grid-template-columns: 1fr 1px 1fr;
  gap: 0.75rem;
  & > div {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
`;

export const VerticalDivider = styled.div`
  width: 1px;
  height: 100%;
  background-color: #ececec;
  margin: 0 auto;
`;
