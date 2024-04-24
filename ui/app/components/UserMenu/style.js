import { Button } from 'antd';
import styled from 'styled-components';

export const Wrapper = styled.div`
  display: grid;
  grid-gap: 10px;
  width: 240px;
`;

export const Item = styled(Button)`
  display: grid;
  grid-template-columns: min-content 1fr;
  align-items: center;
  padding: 0;
  border: none;

  &:hover {
    background: #f0f2f5;
  }
  &:active {
    background: #bcccd1;
  }
  &:hover svg {
    color: rgba(0, 0, 0, 0.85);
  }

  & > span {
    display: flex;
    padding: 5px 8px;
    margin: 0px !important;
    color: rgba(0, 0, 0, 0.85);
  }

  & svg {
    height: 22px;
    width: 22px;
    color: #d9d9d9;
    transition: all 0.6s;
  }
`;
