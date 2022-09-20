/**
 * Downloads file in browser with the passed object as JSON and passed name as file name
 */

const downloadFile = (contents, fileName) => {
  const downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute('href', contents);
  downloadAnchorNode.setAttribute('download', fileName);
  document.body.appendChild(downloadAnchorNode); // required for firefox
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
};

const downloadData = {
  /*
   * @param json data to be downloaded
   * @param fileName Name for the file
   */
  json: (data, fileName) => {
    const jsonStr = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(data, null, 2))}`;
    downloadFile(jsonStr, `${fileName}.json`);
  },

  /*
   * @param text data to be downloaded
   * @param fileName Name for the file
   */
  text: (data, fileName) => {
    const dataStr = `data:text/plain;charset=utf-8,${encodeURIComponent(data)}`;
    downloadFile(dataStr, `${fileName}.txt`);
  },
};

export default downloadData;
