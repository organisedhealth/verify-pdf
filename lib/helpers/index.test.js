const fs = require('fs');
const { default: SignPdf } = require('node-signpdf');
const { Buffer } = require('../../packages/buffer');
const { extractSignature } = require('.');
const VerifyPDFError = require('../VerifyPDFError');
const { createPDF } = require('../testHelpers');

describe('Helpers', () => {
  it('extract signature from signed pdf', async () => {
    const pdfBuffer = await createPDF();
    const p12Buffer = fs.readFileSync(`${__dirname}/../../test-resources/certificate.p12`);
    const signedPdfBuffer = SignPdf.sign(pdfBuffer, p12Buffer);
    const originalSignature = SignPdf.lastSignature;

    const { signatureHex } = extractSignature(signedPdfBuffer);
    const signature = Buffer.from(signatureHex, 'hex');
    expect(Buffer.from(signature, 'latin1').toString('hex').replace(/(?:00)+$/, '')).toBe(originalSignature.replace(/(?:00)+$/, ''));
  });

  it('expects PDF to contain a byteRangeEnd', () => {
    try {
      extractSignature(Buffer.from('/ByteRange [   No End'));
      expect('here').not.toBe('here');
    } catch (e) {
      expect(e instanceof VerifyPDFError).toBe(true);
      expect(e.type).toBe(VerifyPDFError.TYPE_PARSE);
    }
  });
});
