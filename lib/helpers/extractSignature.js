const { Buffer } = require('../../packages/buffer');

const VerifyPDFError = require('../VerifyPDFError');
const { getSignatureMeta, preparePDF } = require('./general');

const getByteRange = (pdfBuffer) => {
  let byteRangePos = pdfBuffer.lastIndexOf('/ByteRange[');
  if (byteRangePos === -1) byteRangePos = pdfBuffer.lastIndexOf('/ByteRange [');
  if (!byteRangePos) {
    throw new VerifyPDFError(
      'Failed to locate ByteRange.',
      VerifyPDFError.TYPE_PARSE,
    );
  }
  const byteRangeEnd = pdfBuffer.indexOf(']', byteRangePos);
  const byteRangeString = pdfBuffer.slice(byteRangePos, byteRangeEnd + 1).toString();
  const byteRangeNumbers = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRangeString);
  const byteRangeArr = byteRangeNumbers[0].split(' ');
  const byteRange = byteRangeArr.map(Number);
  return {
    byteRange,
  };
};

const extractSignature = (pdf) => {
  const pdfBuffer = preparePDF(pdf);
  const { byteRange } = getByteRange(pdfBuffer);
  const endOfByteRange = byteRange[2] + byteRange[3];

  const signedData = Buffer.concat([
    pdfBuffer.slice(byteRange[0], byteRange[1]),
    pdfBuffer.slice(
      byteRange[2],
      endOfByteRange,
    ),
  ]);

  let signatureHex = pdfBuffer
    .slice(
      byteRange[0] + (byteRange[1] + 1),
      byteRange[2] - 1,
    )
    .toString('binary');
  signatureHex = signatureHex.replace(/(?:00)*$/, '');

  if (pdfBuffer.length > endOfByteRange) {
    throw new VerifyPDFError(
      'Failed byte range verification.',
      VerifyPDFError.VERIFY_BYTE_RANGE,
    );
  }

  return {
    byteRange,
    signedData,
    signatureMeta: getSignatureMeta(signedData),
    signatureHex,
  };
};

module.exports = extractSignature;
