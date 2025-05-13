import styled from 'styled-components';

export const Notifications = styled.div`
  display: flex;
  flex-direction: column;
  & > div {
    padding: 12px 0;
  }
  & > div:not(:last-of-type) {
    border-bottom: 1px solid rgb(224, 224, 224);
  }
`;

export const NotificationIcon = styled.div`
  position: relative;
  display: flex;
  align-items: center;
  height: 40px;
`;

export const NotificationsCount = styled.div`
  position: absolute;
  top: 2px;
  right: 0;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background-color: rgb(225, 90, 52);
  color: rgb(255, 255, 255);
  font-size: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
`;

export const Button = styled.div`
  display: flex;
  align-items: center;

  background: transparent;
  border: none;
  padding: 0 20px;

  svg {
    width: 24px;
    height: 24px;
  }
`;

export const PubDate = styled.p`
  font-size: 12px;
`;

export const Badges = styled.div`
  display: flex;
  flex-wrap: wrap;
  gap: 0.125rem;
  margin-top: 4px;
`;

export const Badge = styled.span`
  background-color: rgb(224, 224, 224);
  color: rgb(95, 95, 95);
  padding: 0 5px;
  font-size: 10px;
  border-radius: 5px;
`;
