import styled from 'styled-components';

const UISwitchLabel = styled.span`
  cursor: default;
  color: ${p => (p.disabled ? '#9d9d9d' : '#000')};
`;

export default UISwitchLabel;
