 import React from 'react';
 import { Button } from 'antd';
 import styled from 'styled-components';
 import { PoweroffOutlined, SettingOutlined } from '@ant-design/icons';
 
 const Wrapper = styled.div`
   display: flex;
   flex-direction: column;
   width: 140px;
 `;
 
 const Item = styled(Button)`
   padding: 0 !important;
   border: none !important;
   display: flex !important;
   justify-content: space-between;
   align-items: center;
   padding: 0 5px !important;
   transition: all 0.3s !important;
   &:hover {
     background-color: #f0f0f0 !important;
   }
 `;
 
 const UserMenu = () => (
   <Wrapper>
     <Item
       block
       type="link"
       icon={<SettingOutlined />}
       onClick={() => {
         window.location = '/accounts/edit';
       }}
     >
       Account Settings
     </Item>
     <Item
       block
       type="link"
       icon={<PoweroffOutlined />}
       onClick={() => {
         window.location = '/accounts/logout';
       }}
     >
       Log Out
     </Item>
   </Wrapper>
 );
 
 UserMenu.propTypes = {};
 
 export default UserMenu;
