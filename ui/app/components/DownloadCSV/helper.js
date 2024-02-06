const sanitizeCell = cell => cell?.replace(/,/g, '');

export const formatTable = (columns, data) => {
  const head = columns.map(col => sanitizeCell(col.title)).join(',');
  const body = data.map(row => columns.map(col => sanitizeCell(row[col.dataIndex])).join(','));
  return [head, ...body].join('\n');
};

export const makeCsv = async (table, filename) => {
  const blob = new Blob([table], { type: 'text/csv;charset=utf-8;' });
  if (navigator.msSaveBlob) {
    // In case of IE 10+
    navigator.msSaveBlob(blob, filename);
  } else {
    const link = document.createElement('a');
    if (link.download !== undefined) {
      // Browsers that support HTML5 download attribute
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', filename);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  }
};
