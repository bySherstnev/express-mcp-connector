import sodium from "libsodium-wrappers-sumo";

export interface ExpressSignedRequestInput {
  method: string;
  target: string;
  body?: string;
  keyId: string;
  algorithm: string;
  privateKey: Uint8Array;
  created?: number;
  nonce?: Uint8Array;
  headers?: Readonly<Record<string, string>>;
  allowEmptyKeyId?: boolean;
}

export interface ExpressRequestSignature {
  headers: Record<string, string>;
  signatureData: string;
}

function requireHeaderToken(value: string, field: string): void {
  if (value.length === 0 || /["\r\n]/.test(value)) {
    throw new TypeError(`${field} is invalid`);
  }
}

/** Implements the HTTP Signature format emitted by eXpress Desktop 3.72. */
export function signExpressRequest(
  input: ExpressSignedRequestInput,
): ExpressRequestSignature {
  const method = input.method.toLowerCase();
  if (!/^[a-z]+$/.test(method)) {
    throw new TypeError("method is invalid");
  }
  if (!input.target.startsWith("/") || /[\r\n]/.test(input.target)) {
    throw new TypeError("target is invalid");
  }
  if (!(input.allowEmptyKeyId && input.keyId === "")) {
    requireHeaderToken(input.keyId, "keyId");
  }
  requireHeaderToken(input.algorithm, "algorithm");
  if (input.privateKey.length !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new TypeError("privateKey has an invalid length");
  }

  const created = input.created ?? Math.round(Date.now() / 1_000);
  if (!Number.isSafeInteger(created) || created <= 0) {
    throw new TypeError("created is invalid");
  }
  const nonce =
    input.nonce ?? sodium.randombytes_buf(32);
  if (nonce.length !== 32) {
    throw new TypeError("nonce has an invalid length");
  }

  const nonceBase64 = sodium.to_base64(
    nonce,
    sodium.base64_variants.ORIGINAL,
  );
  const digest =
    input.body === undefined
      ? undefined
      : sodium.to_base64(
          sodium.crypto_hash_sha256(sodium.from_string(input.body)),
          sodium.base64_variants.ORIGINAL,
        );
  const signedHeaders = digest
    ? "(request-target) (created) express-request-nonce digest"
    : "(request-target) (created) express-request-nonce";
  const lines = [
    `(request-target): ${method} ${input.target}`,
    `(created): ${created}`,
    `express-request-nonce: ${nonceBase64}`,
  ];
  if (digest) {
    lines.push(`digest: SHA-256=${digest}`);
  }
  const signatureData = lines.join("\n");
  const signature = sodium.to_base64(
    sodium.crypto_sign_detached(signatureData, input.privateKey),
    sodium.base64_variants.ORIGINAL,
  );

  const headers: Record<string, string> = {
    ...input.headers,
    Signature:
      `keyId="${input.keyId}",algorithm="${input.algorithm}",` +
      `headers="${signedHeaders}",signature="${signature}",created=${created}`,
    "Express-Request-Nonce": nonceBase64,
    "Content-Type": "application/json",
  };
  if (digest) {
    headers.Digest = `SHA-256=${digest}`;
  }

  return { headers, signatureData };
}
