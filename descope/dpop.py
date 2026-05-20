# dpop.py
# DPoP (Demonstrated Proof of Possession) validation — RFC 9449 §7.1-7.2

from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import urlparse

import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from descope.exceptions import ERROR_TYPE_INVALID_TOKEN, AuthException

# Algorithms permitted in a DPoP proof (RFC 9449 §4.2 — no "none", no symmetric)
_ALLOWED_ALGS = {
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA",
}

# Map alg → PyJWT algorithm class for JWK import
_ALG_TO_CLASS = {
    "RS256": RSAAlgorithm, "RS384": RSAAlgorithm, "RS512": RSAAlgorithm,
    "ES256": ECAlgorithm, "ES384": ECAlgorithm, "ES512": ECAlgorithm,
    "PS256": RSAAlgorithm, "PS384": RSAAlgorithm, "PS512": RSAAlgorithm,
}

# Default ports that should be stripped when comparing HTU
_DEFAULT_PORTS = {"https": 443, "http": 80}

# Maximum byte length of a DPoP proof JWT (RFC 9449 §11.1)
_MAX_PROOF_LEN = 8192

# Acceptable clock-skew window around iat
_IAT_BACKWARD_WINDOW = 60   # seconds before now
_IAT_FORWARD_WINDOW = 5     # seconds ahead of now


def _base64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    padding = 4 - len(s) % 4
    s += "=" * (padding % 4)
    return base64.urlsafe_b64decode(s)


def _base64url_encode_nopad(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _normalize_url(raw: str) -> str:
    """
    Normalise a URL for HTU comparison (RFC 9449 §4.2):
    - lowercase scheme and host
    - strip default port
    - drop query string and fragment
    - preserve IPv6 bracket notation
    - normalize empty path to "/"
    """
    p = urlparse(raw)
    scheme = p.scheme.lower()
    host = p.hostname or ""
    port = p.port
    # Rebuild host, preserving IPv6 bracket notation
    if ":" in host:
        host = f"[{host}]"
    # Rebuild netloc without default port
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        netloc = host
    else:
        netloc = f"{host}:{port}"
    # Normalize empty path to "/"
    path = p.path or "/"
    # Reconstruct without query/fragment
    return f"{scheme}://{netloc}{path}"


def _compute_jwk_thumbprint(jwk_dict: dict) -> str:
    """
    Compute the JWK thumbprint (RFC 7638) using SHA-256 and base64url (no padding).
    Only EC, RSA, and OKP key types are supported (matching _ALLOWED_ALGS).
    """
    kty = jwk_dict.get("kty", "")
    if kty == "EC":
        required = {"crv", "kty", "x", "y"}
    elif kty == "RSA":
        required = {"e", "kty", "n"}
    elif kty == "OKP":
        required = {"crv", "kty", "x"}
    else:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unsupported JWK key type for thumbprint: {kty}")

    thumbprint_dict = {k: jwk_dict[k] for k in sorted(required)}
    canonical = json.dumps(thumbprint_dict, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return _base64url_encode_nopad(digest)


def get_dpop_thumbprint(claims: dict) -> str:
    """Extract cnf.jkt from token claims, return empty string if absent."""
    cnf = claims.get("cnf") or {}
    return cnf.get("jkt", "")


def validate_dpop_proof(session_token: str, dpop_proof: str, method: str, request_url: str) -> None:
    """
    Validate a DPoP proof for a DPoP-bound session token (RFC 9449 §7.1-7.2).

    Call after validate_session() when the session token has a cnf.jkt claim.
    Raises AuthException if validation fails.
    Does nothing if session_token has no cnf.jkt.

    NOTE: jti replay protection (RFC 9449 §11.1) is intentionally not implemented.
    A stateless SDK has no shared storage to track seen jti values across requests.
    Callers that require replay protection must implement their own jti store.

    Args:
        session_token (str): The raw session JWT string.
        dpop_proof (str): The value of the DPoP HTTP header from the incoming request.
        method (str): HTTP method of the incoming request (e.g. "GET", "POST").
        request_url (str): Full URL of the incoming request.
    """
    # Decode claims to check for cnf.jkt — no need to validate if not DPoP-bound
    try:
        unverified_claims = jwt.decode(
            session_token,
            options={"verify_signature": False},
            algorithms=list(_ALLOWED_ALGS) + ["RS256", "ES256"],
        )
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unable to decode session token claims: {e}")

    stored_jkt = get_dpop_thumbprint(unverified_claims)
    if not stored_jkt:
        # Token is not DPoP-bound — nothing to validate
        return

    # --- Step 1-2: strip and length check ---
    dpop_proof = dpop_proof.strip()
    if len(dpop_proof.encode()) > _MAX_PROOF_LEN:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof exceeds maximum length")

    # --- Step 3: require non-empty proof ---
    if not dpop_proof:
        raise AuthException(
            400,
            ERROR_TYPE_INVALID_TOKEN,
            "DPoP proof required: access token is DPoP-bound (cnf.jkt present)",
        )

    # --- Step 4-5: split compact JWS ---
    parts = dpop_proof.split(".")
    if len(parts) != 3:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof is not a valid compact JWS")

    # --- Step 6-11: parse and validate header ---
    try:
        header = json.loads(_base64url_decode(parts[0]))
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unable to decode DPoP proof header: {e}")

    if not isinstance(header, dict):
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof header is not a JSON object")

    if header.get("typ") != "dpop+jwt":
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof header must have typ=dpop+jwt")

    alg = header.get("alg", "")
    if alg not in _ALLOWED_ALGS:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"DPoP proof uses unsupported algorithm: {alg}")

    jwk_dict = header.get("jwk")
    if not jwk_dict:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof header is missing jwk")
    if not isinstance(jwk_dict, dict):
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof header jwk is not a JSON object")

    # --- Step 12-13: reject symmetric and private keys ---
    if jwk_dict.get("kty") == "oct":
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof jwk must not be a symmetric key (kty=oct)")
    if "d" in jwk_dict:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof jwk must not contain private key material")

    # --- Step 14-15: load key and verify signature ---
    signing_input = (parts[0] + "." + parts[1]).encode()

    try:
        signature = _base64url_decode(parts[2])
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unable to decode DPoP proof signature: {e}")

    try:
        if alg in _ALG_TO_CLASS:
            alg_class = _ALG_TO_CLASS[alg]
            key = alg_class.from_jwk(json.dumps(jwk_dict))
            alg_instance = jwt.get_algorithm_by_name(alg)
            alg_instance.verify(signing_input, key, signature)
        elif alg == "EdDSA":
            # Try PyJWT's OKP support first; fall back to cryptography library
            try:
                from jwt.algorithms import OKPAlgorithm
                key = OKPAlgorithm.from_jwk(json.dumps(jwk_dict))
                alg_instance = jwt.get_algorithm_by_name(alg)
                alg_instance.verify(signing_input, key, signature)
            except (ImportError, AttributeError):
                # Fallback: verify Ed25519 signature directly via cryptography
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                from cryptography.hazmat.primitives import serialization
                key_bytes = _base64url_decode(jwk_dict["x"])
                public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
                public_key.verify(signature, signing_input)
        else:
            raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unsupported DPoP algorithm: {alg}")
    except AuthException:
        raise
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"DPoP proof signature verification failed: {e}")

    # --- Step 16: decode payload ---
    try:
        payload = json.loads(_base64url_decode(parts[1]))
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unable to decode DPoP proof payload: {e}")

    if not isinstance(payload, dict):
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof payload is not a JSON object")

    # --- Step 17-19: required claims ---
    jti = payload.get("jti", "")
    if not isinstance(jti, str) or not jti:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof payload must have a non-empty jti string claim")

    htm = payload.get("htm", "")
    if not isinstance(htm, str) or not htm:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof payload must have a non-empty htm string claim")

    htu = payload.get("htu", "")
    if not isinstance(htu, str) or not htu:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof payload must have a non-empty htu string claim")

    # --- Step 20: validate HTTP method ---
    if htm != method:
        raise AuthException(
            400,
            ERROR_TYPE_INVALID_TOKEN,
            f"DPoP proof htm claim '{htm}' does not match request method '{method}'",
        )

    # --- Step 21: validate HTU (HTTP URI) ---
    try:
        parsed_htu = urlparse(htu)
        parsed_url = urlparse(request_url)
        if not parsed_htu.scheme or not parsed_htu.netloc:
            raise ValueError("htu is missing scheme or netloc")
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("request_url is missing scheme or netloc")
        norm_htu = _normalize_url(htu)
        norm_url = _normalize_url(request_url)
        if norm_htu != norm_url:
            raise AuthException(
                400,
                ERROR_TYPE_INVALID_TOKEN,
                f"DPoP proof htu '{htu}' does not match request URL '{request_url}'",
            )
    except AuthException:
        raise
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unable to validate DPoP proof htu: {e}")

    # --- Step 22-25: validate iat (issued-at) ---
    iat = payload.get("iat")
    if iat is None:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof payload is missing iat claim")
    try:
        iat = float(iat)
    except (TypeError, ValueError):
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof iat claim is not a number")

    now = time.time()
    diff = now - iat
    if diff <= -_IAT_FORWARD_WINDOW:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof iat is too far in the future")
    if diff >= _IAT_BACKWARD_WINDOW:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof iat has expired (older than 60 seconds)")

    # --- Step 26-28: validate ath (access token hash) ---
    ath = payload.get("ath", "")
    if not isinstance(ath, str) or not ath:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, "DPoP proof payload must have a non-empty ath string claim")

    expected_ath = _base64url_encode_nopad(hashlib.sha256(session_token.encode()).digest())
    if ath != expected_ath:
        raise AuthException(
            400,
            ERROR_TYPE_INVALID_TOKEN,
            "DPoP proof ath claim does not match SHA-256 of the access token",
        )

    # --- Step 29-31: validate JWK thumbprint matches cnf.jkt ---
    try:
        thumbprint = _compute_jwk_thumbprint(jwk_dict)
    except AuthException:
        raise
    except Exception as e:
        raise AuthException(400, ERROR_TYPE_INVALID_TOKEN, f"Unable to compute JWK thumbprint: {e}")

    if thumbprint != stored_jkt:
        raise AuthException(
            400,
            ERROR_TYPE_INVALID_TOKEN,
            "DPoP proof JWK thumbprint does not match the cnf.jkt claim in the access token",
        )
