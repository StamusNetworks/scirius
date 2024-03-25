import React from 'react';

import { IntlProvider } from 'react-intl';
import { render } from 'react-testing-library';

import HomePage from '../index';

describe('<HomePage />', () => {
  it('should render and match the snapshot', () => {
    const {
      container: { firstChild },
    } = render(
      <IntlProvider locale="en">
        <HomePage />
      </IntlProvider>,
    );
    expect(firstChild).toMatchSnapshot();
  });
});
