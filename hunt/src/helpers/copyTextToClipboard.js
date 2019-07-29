/* eslint-disable no-console */
const copyTextToClipboard = (text) => {
    const textArea = document.createElement('textarea');
    textArea.style.position = 'fixed';
    textArea.style.top = 0;
    textArea.style.left = 0;
    textArea.style.width = '2em';
    textArea.style.height = '2em';
    textArea.style.padding = 0;
    textArea.style.border = 'none';
    textArea.style.outline = 'none';
    textArea.style.boxShadow = 'none';
    textArea.style.background = 'transparent';
    textArea.value = text;
    textArea.id = 'ta';
    document.body.appendChild(textArea);
    textArea.select();
    let successful = false;
    try {
        successful = document.execCommand('copy');
    } catch (err) {
        console.warn('Unable to copy');
    }
    document.body.removeChild(textArea);
    return successful;
};

export default copyTextToClipboard;
