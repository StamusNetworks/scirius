import React, { useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { Checkbox, Form, Input, Modal, Select } from 'antd';
import { huntTabs, PAGE_STATE } from 'ui/constants';
import HuntRestError from 'ui/components/HuntRestError';
import { useDispatch, useSelector } from 'react-redux';
import { useInjectSaga } from 'utils/injectSaga';
import { useInjectReducer } from 'utils/injectReducer';
import { useStore } from 'ui/mobx/RootStoreProvider';
import saga from './saga';
import reducer from './reducer';
import selectors from './selectors';

import actions from './actions';

const layout = {
  labelCol: {
    span: 5,
  },
  wrapperCol: {
    span: 19,
  },
};

const FilterSetSaveModal = ({ content, fromPage, title, close }) => {
  useInjectReducer({ key: 'filterSetSave', reducer });
  useInjectSaga({ key: 'filterSetSave', saga });
  const { commonStore } = useStore();
  const dispatch = useDispatch();
  const [form] = Form.useForm();
  const request = useSelector(selectors.makeSelectForm());
  const { error } = request;
  const onFinish = async values => {
    if (await form.validateFields()) {
      const page = fromPage || form.getFieldValue('page');
      dispatch(actions.saveFilterSetRequest({ ...values, page, content }));
      close();
    }
  };

  useEffect(() => {
    form.setFieldsValue({ share: false });
  }, []);

  const noRights = commonStore.user?.isActive && !commonStore.user?.permissions.includes('rules.events_edit');
  const errors = useMemo(() => {
    if (error?.response?.status === 403) {
      if (noRights && form.getFieldValue('share')) {
        return { permission: ['Insufficient permissions. "Shared" is not allowed.'] };
      }
    }
    return {};
  }, [error, form]);

  return (
    <Modal
      data-test="filter-set-save-modal"
      title={title}
      visible
      onCancel={close}
      cancelText={<div data-test="filter-set-save-modal-cancel">Cancel</div>}
      okText={<div data-test="filter-set-save-modal-save">Save</div>}
      okButtonProps={{
        onClick: async () => {
          await form.submit();
        },
      }}
    >
      <HuntRestError errors={errors} />
      <Form form={form} {...layout} onFinish={onFinish}>
        <Form.Item
          label="Name"
          name="name"
          required
          rules={[
            {
              required: true,
              message: 'Please enter a name',
            },
          ]}
        >
          <Input autoFocus data-test="filter-set-save-modal-name" />
        </Form.Item>

        {!fromPage && (
          <Form.Item
            label="Page"
            name="page"
            shouldUpdate
            rules={[
              {
                required: true,
                message: 'Please choose a page',
              },
            ]}
          >
            <Select placeholder="Please select page" data-test="filter-set-save-modal-page">
              {Object.keys(huntTabs)
                .filter(key => key !== PAGE_STATE.filters_list)
                .map(key => (
                  <Select.Option key={huntTabs[key]} value={key} data-test={`filter-set-save-modal-page-${huntTabs[key].toLowerCase()}`}>
                    {huntTabs[key]}
                  </Select.Option> // eslint-disable-line indent
                ))}
            </Select>
          </Form.Item>
        )}
        {fromPage && (
          <Form.Item label="Page">
            <Input disabled defaultValue={huntTabs[fromPage]} data-test="filter-set-save-modal-page-disabled" />
          </Form.Item>
        )}

        {!noRights && (
          <Form.Item
            label="Shared"
            name="share"
            valuePropName="checked"
            help={
              <span>
                Enable: Create Filter Set with All Users
                <br />
                Disable: Create Filter Set only for you
              </span>
            }
          >
            <Checkbox data-test="filter-set-save-modal-shared" />
          </Form.Item>
        )}
        <Form.Item label="Description" name="description">
          <Input.TextArea />
        </Form.Item>
      </Form>
    </Modal>
  );
};

FilterSetSaveModal.propTypes = {
  title: PropTypes.any,
  close: PropTypes.any,
  content: PropTypes.any.isRequired,
  fromPage: PropTypes.any,
};

export default FilterSetSaveModal;
