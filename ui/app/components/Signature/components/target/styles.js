import styled from 'styled-components';

export const Row = styled.div`
  display: grid;
  grid-template-columns: min-content 1fr calc(50% - 0.75rem); // Weird columns to be able to center the arrow
  column-gap: 0.5rem;

  & svg {
    font-size: 1.25rem;
  }
`;

export const Cell = styled.div`
  display: flex;
  align-items: center;
  gap: 0.25rem;

  // Will center the arrow in the middle column
  &:nth-of-type(2) {
    justify-content: center;
  }
`;

export const Target = styled.div`
  display: flex;
  align-items: center;
  justify-content: center;

  color: #8a0000;
  background-color: #ffb9b9;

  padding: 0.125rem;
  border-radius: 50%;

  svg {
    font-size: 1rem;
  }
`;
