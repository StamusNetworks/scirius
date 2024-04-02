import styled from 'styled-components';

export const LimitedCell = styled.div`
  display: flex;
  flex: 1;
  flex-direction: row;
  align-items: flex-start;
`;

export const More = styled.div`
  cursor: default;
  font-size: 12px;
  padding: 2px 4px;
  border-radius: 5px;
  flex-shrink: 0;
`;

export const ValueContainer = styled.div`
  display: flex;
  flex-direction: row;
  gap: 8px;
  flex-wrap: wrap;
  height: 24px;
  overflow: hidden;
`;

export const PopoverContent = styled.div`
  max-width: 250px;

  ol {
    margin-bottom: 0;
    & > li {
      padding-left: 10px;
    }
  }
`;
