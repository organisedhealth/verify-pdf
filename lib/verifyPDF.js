const forge = require('node-forge');
const crypto = require('crypto');
const VerifyPDFError = require('./VerifyPDFError');
const {
  extractSignature,
  getMessageFromSignature,
  getClientCertificate,
  checkForSubFilter,
  preparePDF,
  authenticateSignature,
  sortCertificateChain,
  isCertsExpired,
} = require('./helpers');
const { extractCertificatesDetails } = require('./certificateDetails');

module.exports = (pdf) => {
  const pdfBuffer = preparePDF(pdf);
  checkForSubFilter(pdfBuffer);
  try {
    const { signedData, signatureMeta, signatureHex } = extractSignature(pdfBuffer);
    const message = getMessageFromSignature(signatureHex);
    const {
      certificates,
      rawCapture: {
        signature: sig,
        authenticatedAttributes: attrs,
        digestAlgorithm,
      },
    } = message;
    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();
    const set = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      attrs,
    );
    // Create verifier
    const buf = Buffer.from(forge.asn1.toDer(set).data, 'binary');
    const verifier = crypto.createVerify(`RSA-${hashAlgorithm}`);
    verifier.update(buf);

    const clientCertificate = getClientCertificate(certificates);
    const digest = forge.md[hashAlgorithm]
      .create()
      .update(forge.asn1.toDer(set).data)
      .digest()
      .getBytes();

    const validAuthenticatedAttributes = clientCertificate.publicKey.verify(digest, sig);

    if (!validAuthenticatedAttributes) {
      throw new VerifyPDFError(
        'Wrong authenticated attributes',
        VerifyPDFError.VERIFY_SIGNATURE,
      );
    }

    // Hash of non signature part of PDF
    const pdfHash = crypto.createHash(hashAlgorithm);
    pdfHash.update(signedData);

    // Extracting the message digest
    const { oids } = forge.pki;
    const fullAttrDigest = attrs.find(
      (attr) => forge.asn1.derToOid(attr.value[0].value) === oids.messageDigest,
    );
    const attrDigest = fullAttrDigest.value[1].value[0].value;
    // Compare to message digest to our PDF pdfHash
    const dataDigest = pdfHash.digest();

    const integrity = dataDigest.toString('binary') === attrDigest;

    const sortedCerts = sortCertificateChain(certificates);
    const parsedCerts = extractCertificatesDetails(sortedCerts);
    const authenticity = authenticateSignature(sortedCerts);
    const expired = isCertsExpired(sortedCerts);
    return ({
      verified: integrity && authenticity && !expired,
      authenticity,
      integrity,
      expired,
      meta: { certs: parsedCerts, signatureMeta },
    });
  } catch (error) {
    return ({ verified: false, message: error.message, error });
  }
};
