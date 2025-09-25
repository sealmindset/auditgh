"""Shared helpers for secret scanning scripts (Gitleaks, TruffleHog, etc.)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

DEFAULT_TIMEOUT = 30


def _coerce_int(value: Any) -> Optional[int]:
  if value is None:
    return None
  try:
    return int(value)
  except (TypeError, ValueError):
    try:
      num = float(value)
      return int(num)
    except (TypeError, ValueError):
      return None


def _drop_nulls(data: Dict[str, Any]) -> Dict[str, Any]:
  return {k: v for k, v in data.items() if v is not None and v != ''}


def normalize_gitleaks_record(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
  """Convert a raw Gitleaks finding into a payload compatible with PostgREST."""
  if not isinstance(record, dict):
    return None
  secret = record.get('Secret') or record.get('secret')
  if not secret:
    return None
  description = record.get('Description') or record.get('description') or None
  file_path = record.get('File') or record.get('file') or None
  start_line = _coerce_int(record.get('StartLine') or record.get('startLine'))
  end_line = _coerce_int(record.get('EndLine') or record.get('endLine'))
  rule_id = record.get('RuleID') or record.get('ruleId') or record.get('rule_id') or None
  entropy = record.get('Entropy') or record.get('entropy')

  confidence = 'medium'
  try:
    entropy_val = float(entropy)
  except (TypeError, ValueError):
    entropy_val = None
  if entropy_val is not None:
    if entropy_val >= 5.0:
      confidence = 'high'
    elif entropy_val < 3.5:
      confidence = 'low'

  metadata = _drop_nulls({
    'match': record.get('Match') or record.get('match'),
    'entropy': entropy_val,
    'fingerprint': record.get('Fingerprint') or record.get('fingerprint'),
    'commit': record.get('Commit') or record.get('commit'),
    'author': record.get('Author') or record.get('author'),
    'email': record.get('Email') or record.get('email'),
    'date': record.get('Date') or record.get('date'),
    'tags': record.get('Tags') or record.get('tags'),
  })

  return {
    'detector': 'gitleaks',
    'rule_id': rule_id,
    'description': description,
    'secret': secret,
    'file_path': file_path,
    'line_start': start_line,
    'line_end': end_line,
    'confidence': confidence,
    'validation_status': 'unknown',
    'metadata': metadata,
  }


def normalize_trufflehog_record(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
  """Convert a raw TruffleHog finding into a payload compatible with PostgREST."""
  if not isinstance(record, dict):
    return None
  secret = record.get('Raw') or record.get('raw') or record.get('secret')
  if not secret:
    return None
  description = record.get('Description') or record.get('description') or None
  file_path = (
    record.get('SourceMetadata', {})
      .get('Data', {})
      .get('Filesystem', {})
      .get('file')
    or record.get('SourceMetadata', {})
      .get('filesystem', {})
      .get('file')
    or record.get('File')
    or record.get('file')
  )
  line = (
    record.get('SourceMetadata', {})
      .get('Data', {})
      .get('Filesystem', {})
      .get('line')
    or record.get('line')
    or record.get('StartLine')
    or record.get('startLine')
  )
  line_start = _coerce_int(line)
  rule_id = (
    record.get('RuleID')
    or record.get('rule_id')
    or record.get('DetectorName')
    or record.get('Detector')
    or record.get('detector')
    or record.get('DetectorType')
    or record.get('detectorType')
  )

  severity = str(record.get('Severity') or record.get('severity') or '').lower()
  confidence = 'medium'
  if severity in ('high', 'critical'):
    confidence = 'high'
  elif severity == 'low':
    confidence = 'low'

  metadata = _drop_nulls({
    'detector_name': record.get('DetectorName') or record.get('Detector') or record.get('detector'),
    'detector_type': record.get('DetectorType') or record.get('detectorType'),
    'redacted': record.get('Redacted') or record.get('redacted'),
    'source_metadata': record.get('SourceMetadata') or record.get('source_metadata'),
    'extra': record.get('ExtraData') or record.get('extra'),
  })

  return {
    'detector': 'trufflehog',
    'rule_id': rule_id,
    'description': description,
    'secret': secret,
    'file_path': file_path,
    'line_start': line_start,
    'line_end': line_start,
    'confidence': confidence,
    'validation_status': 'unknown',
    'metadata': metadata,
  }


def ensure_project(postgrest_url: str, repo: Dict[str, Any], logger) -> Optional[int]:
  """Resolve or create a project via PostgREST and return its numeric api_id."""
  base = postgrest_url.rstrip('/')
  name = repo.get('name')
  if not name:
    logger.warning('Repository missing name; cannot ensure project')
    return None

  repo_url = repo.get('html_url') or repo.get('clone_url') or ''
  description = repo.get('description')

  # Try RPC first (preferred)
  try:
    resp = requests.post(
      f"{base}/rpc/ensure_project",
      json={
        'p_name': name,
        'p_repo_url': repo_url,
        'p_description': description,
      },
      timeout=DEFAULT_TIMEOUT,
    )
    if resp.status_code < 400:
      data = resp.json()
      if isinstance(data, list) and data:
        api_id = data[0].get('id') or data[0].get('api_id')
        if isinstance(api_id, int):
          return api_id
  except Exception as exc:  # pragma: no cover - network failure
    logger.warning('ensure_project RPC failed for %s: %s', name, exc)

  # Fallback lookup by name
  try:
    resp = requests.get(
      f"{base}/projects",
      params={'select': 'id,name', 'name': f'eq.{name}'},
      timeout=DEFAULT_TIMEOUT,
    )
    if resp.status_code < 400:
      arr = resp.json() or []
      if arr and isinstance(arr[0].get('id'), int):
        return int(arr[0]['id'])
  except Exception as exc:  # pragma: no cover - network failure
    logger.warning('ensure_project lookup failed for %s: %s', name, exc)

  return None


def persist_secret_leaks(
  postgrest_url: str,
  project_api_id: int,
  repo_short: str,
  items: List[Dict[str, Any]],
  logger,
) -> int:
  """Persist normalized secret leak items via PostgREST RPC."""
  if not items:
    return 0
  base = postgrest_url.rstrip('/')
  payload = []
  for item in items:
    payload.append({
      'detector': item.get('detector', 'other'),
      'repo_short': repo_short,
      'rule_id': item.get('rule_id'),
      'description': item.get('description'),
      'secret': item.get('secret'),
      'file_path': item.get('file_path'),
      'line_start': item.get('line_start'),
      'line_end': item.get('line_end'),
      'confidence': item.get('confidence', 'medium'),
      'validation_status': item.get('validation_status', 'unknown'),
      'metadata': item.get('metadata') or {},
    })

  try:
    resp = requests.post(
      f"{base}/rpc/upsert_secret_leaks",
      json={'p_project_id': project_api_id, 'p_payload': payload},
      timeout=max(DEFAULT_TIMEOUT, 60),
    )
    if resp.status_code >= 400:
      logger.warning('upsert_secret_leaks failed (%s): %s', resp.status_code, resp.text)
      return 0
    try:
      data = resp.json()
      if isinstance(data, int):
        return data
    except Exception:  # pragma: no cover - non-json success
      pass
    return len(payload)
  except Exception as exc:  # pragma: no cover - network failure
    logger.warning('Failed to post upsert_secret_leaks: %s', exc)
    return 0
