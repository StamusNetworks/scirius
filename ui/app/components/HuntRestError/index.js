/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/

import React from 'react';

import PropTypes from 'prop-types';

const HuntRestError = props => {
  if (props.errors === undefined) {
    return null;
  }
  return (
    <div>
      {Object.keys(props.errors).map(field => {
        if (typeof props.errors[field] === 'object') {
          return (
            <div key={field}>
              {props.errors[field].map(error => {
                if (typeof error === 'object') {
                  return (
                    <div key={1} className="alert alert-danger">
                      {field}: <pre style={{ fontSize: 12, color: '#FF0000' }}>{JSON.stringify(error, null, 2)}</pre>
                    </div>
                  );
                }
                return (
                  <div key={error} className="alert alert-danger">
                    {field}: {error}
                  </div>
                );
              })}
            </div>
          );
        }
        const error = props.errors[field];
        return (
          <div key={field}>
            <div key={error} className="alert alert-danger">
              {field}: {error}
            </div>
          </div>
        );
      })}
    </div>
  );
};

HuntRestError.propTypes = {
  errors: PropTypes.any,
};

export default HuntRestError;
