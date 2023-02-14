import styled from 'styled-components';

const FilterActionButton = styled.a`
  padding: 5px !important;
  margin: 0 !important;
  color: #ffffff;
  cursor: ${p => (p.disabled ? 'not-allowed' : 'pointer')};
  &:hover {
    color: #ffffff;
  }
`;

export default FilterActionButton;
