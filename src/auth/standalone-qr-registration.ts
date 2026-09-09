import { randomUUID } from "node:crypto";

import sodium from "libsodium-wrappers-sumo";

import { signExpressRequest } from "./express-http-signature.js";
import {
  EXPRESS_CLIENT_VERSION,
  EXPRESS_JSON_HEADERS,
} from "./express-client-headers.js";

const PLATFORM_PACKAGE_ID = "ru.unlimitedtech.express.desktop";
const MOBILE_TO_WEB_PATH = "/api/v1/authentication/qr/mobile_to_web/request";

export interface QrRegistrationState {
  registrationId: string;
  registrationToken: string;
  registrationKey: Uint8Array;
  signingKeyId: string;
  signingPublicKey: Uint8Array;
  signingPrivateKey: Uint8Array;
  signingAlgorithm: string;
  udid: string;
}

export interface QrStateFactoryOptions {
  randomUuid?: () => string;
  randomBytes?: (length: number) => Uint8Array;
}

export interface QrDeviceMetadata {
  device: string;
  deviceSoftware: string;
  deviceHostname: string | null;
  manufacturer: string;
  platform: "desktop";
  locale: string;
  timezone: string;
  pushes?: boolean;
  permissions?: Readonly<Record<string, unknown>>;
}

export interface ExpressHttpRequest {
  method: "POST";
  url: string;
  target: string;
  headers: Record<string, string>;
  body: string;
}

export interface BuildMobileToWebRequestInput {
  rtsHost: string;
  state: QrRegistrationState;
  device: QrDeviceMetadata;
  created?: number;
  signatureNonce?: Uint8Array;
}

function normalizeHost(host: string): string {
  if (host.trim() !== host || host.length === 0) {
    throw new TypeError("rtsHost must be a valid HTTPS host");
  }
  let url: URL;
  try {
    url = new URL(host.includes("://") ? host : `https://${host}`);
  } catch {
    throw new TypeError("rtsHost is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.pathname !== "/" ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new TypeError("rtsHost is invalid");
  }
  return url.host;
}

export async function createQrRegistrationState(
  options: QrStateFactoryOptions = {},
): Promise<QrRegistrationState> {
  await sodium.ready;
  const uuid = options.randomUuid ?? randomUUID;
  const bytes = options.randomBytes ?? ((length) => sodium.randombytes_buf(length));
  const signingKeys = sodium.crypto_sign_keypair();

  return {
    registrationId: uuid(),
    registrationToken: sodium.to_base64(
      bytes(64),
      sodium.base64_variants.ORIGINAL,
    ),
    registrationKey: bytes(sodium.crypto_secretbox_KEYBYTES),
    signingKeyId: uuid(),
    signingPublicKey: signingKeys.publicKey,
    signingPrivateKey: signingKeys.privateKey,
    signingAlgorithm: signingKeys.keyType,
    udid: uuid(),
  };
}

export function serializeQrPayload(state: QrRegistrationState): string {
  return JSON.stringify({
    registration_id: state.registrationId,
    registration_key: sodium.to_base64(
      state.registrationKey,
      sodium.base64_variants.ORIGINAL,
    ),
    registration_token: state.registrationToken,
    version: 1,
  });
}

export function buildMobileToWebRegistrationRequest(
  input: BuildMobileToWebRequestInput,
): ExpressHttpRequest {
  const host = normalizeHost(input.rtsHost);
  const body = JSON.stringify({
    registration_id: input.state.registrationId,
    registration_token: input.state.registrationToken,
    sign_pub_key: sodium.to_base64(
      input.state.signingPublicKey,
      sodium.base64_variants.ORIGINAL,
    ),
    udid: input.state.udid,
    app_version: EXPRESS_CLIENT_VERSION,
    device: input.device.device,
    device_software: input.device.deviceSoftware,
    device_hostname: input.device.deviceHostname,
    device_meta: {
      pushes: input.device.pushes ?? false,
      timezone: input.device.timezone,
      permissions: input.device.permissions ?? {},
    },
    locale: input.device.locale,
    manufacturer: input.device.manufacturer,
    platform: input.device.platform,
    platform_package_id: PLATFORM_PACKAGE_ID,
  });
  const signed = signExpressRequest({
    method: "POST",
    target: MOBILE_TO_WEB_PATH,
    body,
    keyId: input.state.registrationId,
    algorithm: input.state.signingAlgorithm,
    privateKey: input.state.signingPrivateKey,
    created: input.created,
    nonce: input.signatureNonce,
    headers: EXPRESS_JSON_HEADERS,
  });

  return {
    method: "POST",
    target: MOBILE_TO_WEB_PATH,
    url: `https://${host}${MOBILE_TO_WEB_PATH}`,
    headers: signed.headers,
    body,
  };
}

export async function decryptQrRegistrationData(
  encryptedBase64: string,
  registrationKey: Uint8Array,
): Promise<unknown> {
  await sodium.ready;
  if (registrationKey.length !== sodium.crypto_secretbox_KEYBYTES) {
    throw new TypeError("registrationKey has an invalid length");
  }

  let frame: Uint8Array;
  try {
    frame = sodium.from_base64(
      encryptedBase64,
      sodium.base64_variants.ORIGINAL,
    );
  } catch {
    throw new Error("Registration data is not valid base64");
  }
  if (frame.length <= sodium.crypto_secretbox_NONCEBYTES) {
    throw new Error("Registration data has an invalid encrypted frame");
  }

  const nonce = frame.subarray(0, sodium.crypto_secretbox_NONCEBYTES);
  const ciphertext = frame.subarray(sodium.crypto_secretbox_NONCEBYTES);
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = sodium.crypto_secretbox_open_easy(
      ciphertext,
      nonce,
      registrationKey,
    );
    return JSON.parse(sodium.to_string(plaintext)) as unknown;
  } catch {
    throw new Error("Unable to decrypt or authenticate registration data");
  } finally {
    if (plaintext) {
      sodium.memzero(plaintext);
    }
  }
}
