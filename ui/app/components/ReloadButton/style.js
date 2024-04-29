import { Button } from 'antd';
import styled from 'styled-components';

export const ReloadButton = styled(Button)`
  display: flex;
  align-items: center;

  background: transparent;
  border: none;
  color: rgba(255, 255, 255);
  opacity: 0.65;

  svg {
    width: 24px;
    height: 24px;
  }

  &:hover {
    color: rgba(255, 255, 255);
    opacity: 1;
  }
`;
