import styled from 'styled-components';

import UICard from 'ui/components/UIElements/UICard';

export const Wrapper = styled.div`
  margin-bottom: 1rem;
`;

export const Card = styled(UICard)`
  padding: 0.5rem 1rem;
`;
export const Row = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  grid-gap: 0.5rem;

  margin-bottom: 1rem;
`;

export const Main = styled.div`
  display: grid;
  grid-template-columns: 1fr 2fr;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  @media (max-width: 1000px) {
    grid-template-columns: 1fr;
  }
`;
export const MainRight = styled.div`
  display: grid;
  width: 100%;
  grid-template-columns: 1fr 1fr;
  gap: 0.5rem;
`;

export const Divider = styled.div`
  width: calc(100% + 2rem);
  transform: translateX(-1rem);
  height: 1px;
  background-color: #ececec;
  margin: 0.25rem 0;
`;

export const Title = styled.span`
  font-size: 1rem;
  font-weight: 600;
`;

export const Label = styled.span`
  white-space: nowrap;
  text-transform: capitalize;
  font-size: 0.75rem;
  font-weight: 700;
  margin: 0;
`;

export const LabelRow = styled.div`
  display: flex;
  align-items: center;
  column-gap: 0.5rem;
  flex-wrap: wrap;
`;

export const Field = styled.div`
  display: flex;
  flex-direction: column;
  max-width: 100%;
`;

export const Value = styled.div`
  color: rgba(0, 0, 0, 0.65);
  white-space: wrap;
  word-break: break-all;
  font-weight: 400;
`;

export const ValueAsLink = styled.a`
  color: rgba(0, 0, 0, 0.65);
  font-weight: 400;
  text-decoration: dotted;
  word-break: break-all;
`;

export const Tags = styled.div`
  display: flex;
  gap: 0.25rem;
  flex-wrap: wrap;
`;

export const Tag = styled.span`
  line-height: 1.25;
  padding: 0.125rem 0.35rem;
  border-radius: 1rem;

  font-weight: 500;
  font-size: 0.65rem;

  ${({ color }) => {
    switch (color) {
      case 'yellow':
        return `
          color: #373d00;
          background-color: #e6eda9;
        `;
      case 'red':
        return `
          color: #8a0000;
          background-color: #ffb9b9;
        `;
      case 'purple':
        return `
          color: #2a003d;
          background-color: #f5cffd;
        `;
      default:
        return `
          color: #100086;
          background-color: #e4e1ff;
        `;
    }
  }}
`;

export const ShowSignatureTextButton = styled.button`
  background-color: transparent;
  border: none;
`;

export const SigContent = styled.div`
  & pre {
    white-space: pre-wrap;
    display: block;
    padding: 10px;
    height: 100%;
    font-size: 14px;
    line-height: 1.66667;
    word-break: break-all;
    word-wrap: break-word;
    color: #747276;
    background-color: white;
    border: 1px solid #ccc;
    border-radius: 1px;
    margin-bottom: 0;
  }

  & .highlight {
    height: 100%;
  }

  & .highlight .err {
    border: none;
  }
`;

export const MainInfosCard = styled(Card)`
  .ant-card-body {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    &:before {
      content: none;
    }
  }
`;

export const InfoRow = styled.div`
  display: grid;
  grid-template-columns: ${({ span }) => (span ? '1fr' : '1fr 1fr')};
  column-gap: 1.5rem;
  row-gap: 0.5rem;
`;
