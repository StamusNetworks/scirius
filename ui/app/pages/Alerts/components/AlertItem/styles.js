import styled from 'styled-components';

export const DlHorizontal = styled.dl`
  & .dl-item {
    display: grid;
    grid-template-columns: 1fr 2fr;
    align-items: center;
  }
  & dt {
    justify-self: end;
  }
  & dd {
    overflow: hidden;
    -o-text-overflow: ellipsis;
    text-overflow: ellipsis;
    margin-left: 20px;
    margin-bottom: 0;
  }
`;
