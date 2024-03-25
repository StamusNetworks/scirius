import { Link } from 'react-router-dom';
import styled from 'styled-components';

export default styled(Link)`
  color: #222;
  display: block;
  margin-left: 25px;
  padding-left: 10px;
  padding-top: 2px;
  padding-bottom: 2px;
  &:hover {
    background: #e6e6e6;
    color: #000;
    border-radius: 5px 0 0 5px;
  }
`;
