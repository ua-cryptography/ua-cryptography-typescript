/** Object identifiers of the Ukrainian PKI and of the formats here (C# Oids.cs; docs/signature-formats.md, section 2). */
export const Oid = {
  // Ukrainian algorithms, arc 1.2.804.2.1.1.1
  Gost34311: '1.2.804.2.1.1.1.1.2.1',
  Dstu7564_256: '1.2.804.2.1.1.1.1.2.2.1',
  Dstu7564_384: '1.2.804.2.1.1.1.1.2.2.2',
  Dstu7564_512: '1.2.804.2.1.1.1.1.2.2.3',
  /** DSTU 4145 key whose octet strings are little-endian; the same OID names "DSTU 4145 with GOST 34.311". */
  Dstu4145Le: '1.2.804.2.1.1.1.1.3.1.1',
  /** DSTU 4145 key whose octet strings are big-endian. */
  Dstu4145Be: '1.2.804.2.1.1.1.1.3.1.1.1.1',
  Dstu4145WithGost34311: '1.2.804.2.1.1.1.1.3.1.1',
  Dstu4145WithDstu7564: '1.2.804.2.1.1.1.1.3.6.1.1',
  /** The i-th curve of table Г.1 is this prefix followed by i. */
  NamedCurvePrefix: '1.2.804.2.1.1.1.1.3.1.1.2.',
  TspPolicyGost34311: '1.2.804.2.1.1.1.2.3.1',
  TspPolicyDstu7564: '1.2.804.2.1.1.1.2.3.4.1.1',

  Sha1: '1.3.14.3.2.26',
  Sha256: '2.16.840.1.101.3.4.2.1',

  // X.500 attribute types
  CommonName: '2.5.4.3',
  Surname: '2.5.4.4',
  SerialNumber: '2.5.4.5',
  Country: '2.5.4.6',
  Locality: '2.5.4.7',
  State: '2.5.4.8',
  Street: '2.5.4.9',
  Organization: '2.5.4.10',
  OrganizationalUnit: '2.5.4.11',
  Title: '2.5.4.12',
  GivenName: '2.5.4.42',
  OrganizationIdentifier: '2.5.4.97',
  EmailAddress: '1.2.840.113549.1.9.1',

  // X.509 extensions (RFC 5280)
  SubjectKeyIdentifier: '2.5.29.14',
  KeyUsage: '2.5.29.15',
  BasicConstraints: '2.5.29.19',
  AuthorityKeyIdentifier: '2.5.29.35',
  ExtendedKeyUsage: '2.5.29.37',
  AuthorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  SubjectInfoAccess: '1.3.6.1.5.5.7.1.11',
  AccessOcsp: '1.3.6.1.5.5.7.48.1',
  AccessCaIssuers: '1.3.6.1.5.5.7.48.2',
  AccessTimeStamping: '1.3.6.1.5.5.7.48.3',
  KeyPurposeTimeStamping: '1.3.6.1.5.5.7.3.8',
  KeyPurposeOcspSigning: '1.3.6.1.5.5.7.3.9',

  // CMS (RFC 5652) and its attributes
  Data: '1.2.840.113549.1.7.1',
  SignedData: '1.2.840.113549.1.7.2',
  TstInfo: '1.2.840.113549.1.9.16.1.4',
  ContentType: '1.2.840.113549.1.9.3',
  MessageDigest: '1.2.840.113549.1.9.4',
  SigningTime: '1.2.840.113549.1.9.5',
  SigningCertificate: '1.2.840.113549.1.9.16.2.12',
  SigningCertificateV2: '1.2.840.113549.1.9.16.2.47',
  SignatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',
  ContentTimeStamp: '1.2.840.113549.1.9.16.2.20',
  CertificateRefs: '1.2.840.113549.1.9.16.2.21',
  RevocationRefs: '1.2.840.113549.1.9.16.2.22',
  CertValues: '1.2.840.113549.1.9.16.2.23',
  RevocationValues: '1.2.840.113549.1.9.16.2.24',

  // OCSP (RFC 6960)
  OcspBasic: '1.3.6.1.5.5.7.48.1.1',

  /** The Sun JKS key protector. */
  JksKeyProtector: '1.3.6.1.4.1.42.2.17.1.1',
} as const;
