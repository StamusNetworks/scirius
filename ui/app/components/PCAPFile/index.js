import React, { useState } from 'react';
import { useSelector } from 'react-redux';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Empty, Modal, Spin } from 'antd';
import moment from 'moment';
import { CheckCircleOutlined, CloseCircleOutlined, DownloadOutlined, MinusCircleOutlined } from '@ant-design/icons';
import styled from 'styled-components';

import * as config from 'config/Api';
import constants from 'ui/constants';

const Warning = styled.div`
  text-align: center;
  color: red;
  padding-bottom: 10px;
`;

const Container = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  justify-items: center;
`;

const Download = styled.div`
  display: grid;
  grid-template-columns: 1fr min-content;
  grid-gap: 10px;
`;

const Progress = styled.div`
  display: grid;
  grid-template-columns: 1fr min-content;
  align-items: center;
  padding: 0 5px;
  margin: 5px 0;
  border: ${({ loading, data }) => (data && !(loading === 'true') ? '1px solid #3f9c35' : '1px solid #ccc')};
  background: ${({ loading, data }) => (data && !(loading === 'true') ? '#e9f4e9' : 'none')};
  transition: all 0.3s;
`;

const ModalFooter = styled.div`
  text-align: center;
  color: ${({ pcapUploadingError, pcapExtractingError, pcapRetrievingError, pcapAutoDownloadingError }) =>
    pcapUploadingError || pcapExtractingError || pcapRetrievingError || pcapAutoDownloadingError ? 'red' : '#3f9c35'};
  opacity: ${({ pcapDownloading }) => (!pcapDownloading ? 1 : 0)};
  transition: all 1s;
`;

const PCAPFile = ({ alertData }) => {
  const isEnterpriseEdition = useSelector(({ global }) => !!global.ee);

  const [showPCAPdownloadProgress, setShowPCAPdownloadProgress] = useState(false);
  const [pcapDownloading, setPcapDownloading] = useState(false);
  const [pcapUploadingData, setPcapUploadingData] = useState(null);
  const [pcapUploading, setPcapUploading] = useState(false);
  const [pcapUploadingError, setPcapUploadingError] = useState('');
  const [pcapExtractingData, setPcapExtractingData] = useState(null);
  const [pcapExtracting, setPcapExtracting] = useState(false);
  const [pcapExtractingError, setPcapExtractingError] = useState('');
  const [pcapRetrievingData, setPcapRetrievingData] = useState(null);
  const [pcapRetrieving, setPcapRetrieving] = useState(false);
  const [pcapRetrievingError, setPcapRetrievingError] = useState('');
  const [pcapAutoDownloadingData, setPcapAutoDownloadingData] = useState(null);
  const [pcapAutoDownloading, setPcapAutoDownloading] = useState(false);
  const [pcapAutoDownloadingError, setPcapAutoDownloadingError] = useState('');

  const downloadPCAPFile = async () => {
    setShowPCAPdownloadProgress(true);
    setPcapDownloading(true);
    setPcapUploadingData(null);
    setPcapUploading(true);
    setPcapUploadingError('');
    setPcapExtractingData(null);
    setPcapExtractingError('');
    setPcapRetrievingData(null);
    setPcapRetrievingError('');
    setPcapAutoDownloadingData(null);
    setPcapAutoDownloadingError('');

    const { host, _id: alertId } = alertData;
    let upload;
    let extraction;
    let retrieve;

    const downloadPCAP = async () => {
      try {
        const href = `${config.API_URL + config.FILESTORE_PCAP}${alertId}/download/`;
        const element = document.createElement('a');
        element.setAttribute('href', href);
        element.setAttribute('download', `${element.href.split('/')[element.href.split('/').length - 1]}.pcap`);
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);

        window.URL.revokeObjectURL(href);

        setPcapDownloading(false);
        setPcapAutoDownloadingData('downloaded');
        setPcapAutoDownloading(false);
      } catch (e) {
        setPcapDownloading(false);
        setPcapAutoDownloading(false);
        setPcapAutoDownloadingError(e.response?.data?.error || 'Downloading PCAP from SSP to browser failed');
      }
    };

    // 1. Upload the alert to the Probe
    try {
      // Prepare the data for the request https://developer.mozilla.org/en-US/docs/Web/API/FormData/Using_FormData_Objects
      const formData = new FormData();
      formData.append('file', new Blob([JSON.stringify(alertData)], { type: 'application/json' }));
      const { data } = await axios.post(`${config.API_URL + config.FILESTORE_PCAP}upload/?host=${host}`, formData);
      upload = data.upload;
      if (upload !== 'done') throw new Error();
    } catch (e) {
      setPcapDownloading(false);
      setPcapUploading(false);
      setPcapUploadingError(e.response?.data?.error || 'Uploading the alert to the Probe failed');
      return;
    }

    if (upload === 'done') {
      setPcapUploadingData(upload);
      setPcapUploading(false);
      setPcapExtracting(true);

      // 2. Extract the PCAP on the Probe
      try {
        const { data } = await axios.post(`${config.API_URL + config.FILESTORE_PCAP}${alertId}/extract_pcap/?host=${host}`);
        extraction = data.extraction;
        if (extraction !== 'done') throw new Error();
      } catch (e) {
        setPcapDownloading(false);
        setPcapExtracting(false);
        setPcapExtractingError(e.response?.data?.error || 'Extracting the PCAP on the Probe failed');
        return;
      }

      if (extraction === 'done') {
        setPcapExtractingData(extraction);
        setPcapExtracting(false);

        if (isEnterpriseEdition) {
          setPcapRetrieving(true);

          // 3. Retrieve PCAP from Probe to SSP in Scirius EE
          try {
            const { data } = await axios.get(`${config.API_URL + config.FILESTORE_PCAP}${alertId}/retrieve/?host=${host}`);
            retrieve = data.retrieve;
            if (retrieve !== 'done') throw new Error();
            setPcapRetrievingData(retrieve);
            setPcapRetrieving(false);
          } catch (e) {
            setPcapDownloading(false);
            setPcapRetrieving(false);
            setPcapRetrievingError(e.response?.data?.error || 'Retrieving PCAP from Probe to SSP failed');
            return;
          }
        }

        setPcapAutoDownloading(true);
        // 4. Download PCAP from SSP to browser
        downloadPCAP();
      }
    }
  };

  const progressData = [
    { key: 1, text: 'Send PCAP extraction request to probe', data: pcapUploadingData, loading: pcapUploading, error: pcapUploadingError },
    { key: 2, text: 'Extract pcap file from probe pcap store', data: pcapExtractingData, loading: pcapExtracting, error: pcapExtractingError },
    { key: 3, text: 'Retrieve extracted pcap file from probe', data: pcapRetrievingData, loading: pcapRetrieving, error: pcapRetrievingError },
    {
      key: 4,
      text: 'Starting download of extracted pcap file',
      data: pcapAutoDownloadingData,
      loading: pcapAutoDownloading,
      error: pcapAutoDownloadingError,
    },
  ];

  return (
    <React.Fragment>
      {!alertData.capture_file && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />}
      {alertData.capture_file && (
        <div>
          <Container>
            <div>
              <strong>Probe: </strong>
              {alertData.host}
            </div>
            <div>
              <strong>File: </strong>starting{' '}
              {moment
                .unix(parseInt(alertData.capture_file.split('/')[alertData.capture_file.split('/').length - 1].split('-')[1], 10))
                .format(constants.DATE_TIME_FORMAT)}
            </div>
            <Download>
              <span>PCAP Download </span>
              {!pcapDownloading && (
                <a
                  onClick={e => {
                    e.preventDefault();
                    downloadPCAPFile();
                  }}
                >
                  <DownloadOutlined />
                </a>
              )}
              {pcapDownloading && <Spin size="small" />}
            </Download>
          </Container>
          <Warning>
            WARNING: The PCAP trace can contain malicious files or payloads inside ! DO NOT execute, run or activate the extracted contents in non
            protected or non sand boxed environments. Stamus Networks is not responsible for any damage to your systems and infrastructure that might
            occur as a consequence of downloading them.
          </Warning>
          <Modal
            title="PCAP file download progress"
            visible={showPCAPdownloadProgress}
            onCancel={() => setShowPCAPdownloadProgress(false)}
            footer={
              <ModalFooter
                pcapDownloading={pcapDownloading}
                pcapUploadingError={pcapUploadingError}
                pcapExtractingError={pcapExtractingError}
                pcapRetrievingError={pcapRetrievingError}
                pcapAutoDownloadingError={pcapAutoDownloadingError}
              >
                {pcapUploadingError || pcapExtractingError || pcapRetrievingError || pcapAutoDownloadingError || <b>Download Complete</b>}
              </ModalFooter>
            }
          >
            {progressData.map(pd => {
              if (!isEnterpriseEdition && pd.key === 3) return null;

              return (
                <Progress key={pd.key} data={pd.data} loading={pd.loading.toString()}>
                  <span>{pd.text}</span>
                  {!pd.data && !pd.loading && !pd.error && <MinusCircleOutlined />}
                  {pd.loading && <Spin size="small" style={{ display: 'grid' }} />}
                  {pd.data && !pd.loading && <CheckCircleOutlined style={{ color: '#3f9c35' }} />}
                  {pd.error && !pd.loading && <CloseCircleOutlined style={{ color: 'red' }} />}
                </Progress>
              );
            })}
          </Modal>
        </div>
      )}
    </React.Fragment>
  );
};

PCAPFile.propTypes = {
  alertData: PropTypes.object,
};

export default PCAPFile;
