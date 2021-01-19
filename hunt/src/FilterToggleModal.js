import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Modal, Icon, Button, Form, FormGroup, FormControl, Col } from 'patternfly-react';
import * as config from 'hunt_common/config/Api';
import HuntRestError from './components/HuntRestError';

export default class FilterToggleModal extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      comment: '',
      new_index: 0,
      errors: undefined,
    };
    this.close = this.close.bind(this);
    this.submit = this.submit.bind(this);
    this.handleChange = this.handleChange.bind(this);
    this.handleCommentChange = this.handleCommentChange.bind(this);
    this.onFieldKeyPress = this.onFieldKeyPress.bind(this);
  }

  componentDidUpdate(prevProps) {
    if (prevProps.action !== this.props.action) {
      // Move to top / Launch dialog init with 0, then event to update new_index
      // eslint-disable-next-line react/no-did-update-set-state
      this.setState({ new_index: 0 });

      if (this.props.action === 'movebottom') {
        // eslint-disable-next-line react/no-did-update-set-state
        this.setState({ new_index: this.props.last_index });
      }
    }
  }

  onFieldKeyPress(keyEvent) {
    if (keyEvent.key === 'Enter') {
      if (this.state.new_index < 0) {
        // Propagate event to trigger validation error
        return;
      }
      keyEvent.stopPropagation();
      keyEvent.preventDefault();
    }
  }

  // eslint-disable-next-line class-methods-use-this
  onModalClick(e) {
    // Stopping event propagation is required since the modal is the children of a list item that
    // will also react to clicks
    e.stopPropagation();
  }

  handleChange(event) {
    const val = parseInt(event.target.value, 10);
    if (val >= 0) {
      this.setState({ new_index: val });
    }
  }

  handleCommentChange(event) {
    this.setState({ comment: event.target.value });
  }

  submit() {
    let data;
    if (['move', 'movetop', 'movebottom'].indexOf(this.props.action) !== -1) {
      data = { index: this.state.new_index, comment: this.state.comment };
      axios
        .patch(`${config.API_URL}${config.PROCESSING_PATH}${this.props.data.pk}/`, data)
        .then(() => {
          this.props.needUpdate();
          this.close();
        })
        .catch((error) => {
          this.setState({ errors: error.response.data });
        });
    }
    if (this.props.action === 'delete') {
      data = { comment: this.state.comment };
      axios({
        url: `${config.API_URL}${config.PROCESSING_PATH}${this.props.data.pk}/`,
        data,
        method: 'delete',
      })
        .then(() => {
          this.props.needUpdate();
          this.close();
        })
        .catch((error) => {
          this.setState({ errors: error.response.data });
        });
    }
  }

  close() {
    this.setState({ errors: undefined });
    this.props.close();
  }

  render() {
    let { action } = this.props;
    switch (action) {
      case 'movetop':
        action = 'Move to top';
        break;
      case 'move':
        action = 'Move';
        break;
      case 'movebottom':
        action = 'Move to bottom';
        break;
      case 'delete':
        action = 'Delete';
        break;
      default:
        break;
    }
    return (
      <Modal show={this.props.show} onHide={this.close}>
        <div onClick={this.onModalClick}>
          <Modal.Header>
            <button type="button" className="close" onClick={this.close} aria-hidden="true" aria-label="Close">
              <Icon type="pf" name="close" />
            </button>
            {this.props.data && (
              <Modal.Title>
                {action} {this.props.data.action} at current position {this.props.data.index}
              </Modal.Title>
            )}
          </Modal.Header>
          <Modal.Body>
            <HuntRestError errors={this.state.errors} />
            <Form horizontal>
              {this.props.action === 'move' && (
                <FormGroup key="index" controlId="index" disabled={false}>
                  <Col sm={3}>
                    <strong>New index</strong>
                  </Col>
                  <Col sm={9}>
                    <FormControl
                      type="number"
                      min={0}
                      max={50000}
                      disabled={false}
                      defaultValue={0}
                      onChange={this.handleChange}
                      onKeyPress={(e) => this.onFieldKeyPress(e)}
                    />
                  </Col>
                </FormGroup>
              )}
              <div className="form-group">
                <div className="col-sm-9">
                  <strong>Optional comment</strong>
                  <textarea value={this.state.comment} cols={70} onChange={this.handleCommentChange} />
                </div>
              </div>
            </Form>
          </Modal.Body>
          <Modal.Footer>
            <Button bsStyle="default" className="btn-cancel" onClick={this.close}>
              Cancel
            </Button>
            <Button bsStyle="primary" onClick={this.submit}>
              Submit
            </Button>
          </Modal.Footer>
        </div>
      </Modal>
    );
  }
}
FilterToggleModal.propTypes = {
  action: PropTypes.any,
  last_index: PropTypes.any,
  data: PropTypes.any,
  show: PropTypes.any,
  close: PropTypes.func,
  needUpdate: PropTypes.func,
};
