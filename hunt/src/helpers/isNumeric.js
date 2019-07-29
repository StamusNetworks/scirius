const isNumeric = (n) => !Number.isNaN(parseFloat(n)) && Number.isFinite(n);

export default isNumeric;
