import React, { useState, useEffect } from 'react';

import { InboxOutlined } from '@ant-design/icons';
import { Modal } from 'antd';
import moment from 'moment';

import { EDITION } from 'ui/config';

import { Notifications, Badges, Badge, PubDate, NotificationIcon, NotificationsCount, Button } from './newsfeed.styles';

export const Newsfeed = () => {
  const [modal, setModal] = useState(false);
  const [rssFeed, setRssFeed] = useState([]);

  const minDate = moment().subtract(14, 'day');
  const lastRead = localStorage.getItem('notifications-last-read');
  const unreadLimit = moment(lastRead).isAfter(minDate) ? lastRead : minDate;
  const unreadCount = rssFeed.filter(item => moment(item.pubDate).isAfter(unreadLimit)).length;

  useEffect(() => {
    (async () => {
      const EE = await fetchRssFeed('/blog/tag/clear-ndr-enterprise/rss.xml');
      if (EDITION === 'enterprise') {
        setRssFeed(EE.slice(0, 10));
      } else {
        const CE = await fetchRssFeed('/blog/tag/clear-ndr-community/rss.xml');
        const combinedFeed = [...CE, ...EE];
        const uniqueFeed = combinedFeed.filter((item, index, self) => index === self.findIndex(t => t.title === item.title));
        const sortedFeed = uniqueFeed.sort((a, b) => moment(b.pubDate).valueOf() - moment(a.pubDate).valueOf());
        setRssFeed(sortedFeed.slice(0, 10));
      }
    })();
  }, []);

  const handleClose = () => {
    localStorage.setItem('notifications-last-read', new Date());
    setModal(false);
  };

  return (
    <div>
      <Button onClick={setModal}>
        <NotificationIcon>
          {!!unreadCount && <NotificationsCount>{unreadCount}</NotificationsCount>}
          <InboxOutlined />
        </NotificationIcon>
      </Button>
      <Modal open={modal} onOk={handleClose} onCancel={handleClose}>
        <Notifications>
          {rssFeed.map(item => (
            <div key={item.title}>
              <PubDate>{moment(item.pubDate).format('MMM D, YYYY')}</PubDate>
              <a
                href={item.link}
                target="_blank"
                rel="noopener noreferrer"
                style={{ fontWeight: moment(item.pubDate).isAfter(unreadLimit) ? 'bold' : 'normal' }}
              >
                {item.title}
              </a>
              <Badges>
                {item.categories?.map(category => (
                  <Badge>{category}</Badge>
                ))}
              </Badges>
            </div>
          ))}
        </Notifications>
      </Modal>
    </div>
  );
};

const fetchRssFeed = async url => {
  const tracking =
    EDITION === 'enterprise'
      ? '?utm_source=clear-ndr-enterprise&utm_medium=newsfeed&utm_campaign=clear-ndr-news'
      : '?utm_source=clear-ndr-community&utm_medium=newsfeed&utm_campaign=clear-ndr-news';
  const response = await fetch(url);
  const text = await response.text();
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(text, 'text/xml');
  return Array.from(xmlDoc.getElementsByTagName('item')).map(item => ({
    title: item.getElementsByTagName('title')[0]?.textContent,
    link: item.getElementsByTagName('link')[0]?.textContent + tracking,
    pubDate: item.getElementsByTagName('pubDate')[0]?.textContent,
    description: item.getElementsByTagName('description')[0]?.textContent,
    categories: Array.from(item.getElementsByTagName('category')).map(category => category.textContent),
  }));
};
