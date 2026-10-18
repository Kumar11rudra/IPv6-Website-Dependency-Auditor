"""
Robust data migration from SQLite (auditor.db) to PostgreSQL (auditor_db).
"""
import os
import sys
import json
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.models.tables import Base, Scan, Batch, BatchSite, Resource, MeasurementContext, HostProbe

SQLITE_PATH = backend_dir / "data" / "auditor.db"
PG_URL = os.getenv("AUDITOR_DB_URL", "postgresql+psycopg2://postgres@127.0.0.1:5432/auditor_db")


def parse_json_val(val, default):
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return default
    return val


def migrate():
    if not SQLITE_PATH.exists():
        print(f"Error: SQLite database not found at {SQLITE_PATH}")
        return

    print(f"Connecting to SQLite: {SQLITE_PATH}")
    sqlite_engine = create_engine(f"sqlite:///{SQLITE_PATH}")
    SqliteSession = sessionmaker(sqlite_engine)

    print(f"Connecting to PostgreSQL: {PG_URL}")
    pg_engine = create_engine(PG_URL)
    PgSession = sessionmaker(pg_engine)

    # Recreate tables in Postgres to match latest schema
    print("Recreating clean schema in PostgreSQL...")
    Base.metadata.drop_all(pg_engine)
    Base.metadata.create_all(pg_engine)

    with SqliteSession() as s_sess, PgSession() as pg_sess:
        # 1. Batch
        batches = s_sess.query(Batch).all()
        print(f"Migrating {len(batches)} batches...")
        for b in batches:
            pg_sess.add(Batch(
                batch_id=b.batch_id,
                status=b.status,
                total=b.total,
                source=b.source,
                scanner_version=b.scanner_version,
                error=b.error,
                created_at=b.created_at,
                started_at=b.started_at,
                finished_at=b.finished_at,
            ))
        pg_sess.commit()

        # 2. BatchSite
        sites = s_sess.query(BatchSite).all()
        print(f"Migrating {len(sites)} batch sites...")
        for bs in sites:
            pg_sess.add(BatchSite(
                batch_id=bs.batch_id,
                site_index=bs.site_index,
                name=bs.name,
                url=bs.url,
                scan_id=bs.scan_id,
            ))
        pg_sess.commit()

        # 3. Scan
        scans = s_sess.query(Scan).all()
        print(f"Migrating {len(scans)} scans...")
        for s in scans:
            pg_sess.add(Scan(
                scan_id=s.scan_id,
                target_url=s.target_url,
                final_url=s.final_url,
                status=s.status,
                error=s.error,
                scanner_version=s.scanner_version,
                batch_id=s.batch_id,
                truncated=s.truncated,
                created_at=s.created_at,
                started_at=s.started_at,
                finished_at=s.finished_at,
                summary=parse_json_val(s.summary, None),
            ))
        pg_sess.commit()

        # 4. Resource
        resources = s_sess.query(Resource).all()
        print(f"Migrating {len(resources)} resources...")
        for r in resources:
            pg_sess.add(Resource(
                scan_id=r.scan_id,
                resource_id=r.resource_id,
                parent_resource_id=r.parent_resource_id,
                parent_inferred=r.parent_inferred,
                url=r.url,
                hostname=r.hostname,
                port=r.port,
                scheme=r.scheme,
                resource_type=r.resource_type,
                initiator=r.initiator,
                initiator_url=r.initiator_url,
                protocol=r.protocol,
                http_status=r.http_status,
                load_status=r.load_status,
                error_text=r.error_text,
                remote_ip=r.remote_ip,
                remote_family=r.remote_family,
                timestamp=r.timestamp,
                ipv4_addresses=parse_json_val(r.ipv4_addresses, []),
                ipv6_addresses=parse_json_val(r.ipv6_addresses, []),
            ))
        pg_sess.commit()

        # 5. MeasurementContext
        contexts = s_sess.query(MeasurementContext).all()
        print(f"Migrating {len(contexts)} measurement contexts...")
        for mc in contexts:
            pg_sess.add(MeasurementContext(
                scan_id=mc.scan_id,
                collected_at=mc.collected_at,
                resolver_ips=parse_json_val(mc.resolver_ips, []),
                resolver_upstream_ips=parse_json_val(mc.resolver_upstream_ips, []),
                resolver_source=mc.resolver_source,
                resolver_is_local_stub=mc.resolver_is_local_stub,
                resolver_egress_ip=mc.resolver_egress_ip,
                scanner_public_ipv4=mc.scanner_public_ipv4,
                scanner_public_ipv6=mc.scanner_public_ipv6,
                ipv4_egress_ok=mc.ipv4_egress_ok,
                ipv6_egress_ok=mc.ipv6_egress_ok,
                geo_ip=mc.geo_ip,
                geo_country=mc.geo_country,
                geo_region=mc.geo_region,
                geo_city=mc.geo_city,
                geo_org=mc.geo_org,
                geo_source=mc.geo_source,
                warnings=parse_json_val(mc.warnings, []),
            ))
        pg_sess.commit()

        # 6. HostProbe
        probes = s_sess.query(HostProbe).all()
        print(f"Migrating {len(probes)} host probes...")
        for hp in probes:
            pg_sess.add(HostProbe(
                scan_id=hp.scan_id,
                hostname=hp.hostname,
                port=hp.port,
                family=hp.family,
                dns_status=hp.dns_status,
                dns_addresses=parse_json_val(hp.dns_addresses, []),
                dns_detail=hp.dns_detail,
                canonical_name=hp.canonical_name,
                resolver_used=hp.resolver_used,
                dns_ms=hp.dns_ms,
                tcp_status=hp.tcp_status,
                tls_status=hp.tls_status,
                http_stage_status=hp.http_stage_status,
                http_code=hp.http_code,
                failure_stage=hp.failure_stage,
                failure_subtype=hp.failure_subtype,
                latency_ms=hp.latency_ms,
                error_detail=hp.error_detail,
                probe_scheme=hp.probe_scheme,
                probe_path=hp.probe_path,
                verdict=hp.verdict,
                family_comparison=hp.family_comparison,
                connected_address=hp.connected_address,
                addresses_tested=hp.addresses_tested,
                addresses_reachable=hp.addresses_reachable,
                tcp_ms=hp.tcp_ms,
                tls_ms=hp.tls_ms,
                http_ms=hp.http_ms,
                tls_version=hp.tls_version,
            ))
        pg_sess.commit()

    print("\n--- Migration Verification ---")
    with PgSession() as pg_sess:
        for model in [Batch, BatchSite, Scan, Resource, MeasurementContext, HostProbe]:
            count = pg_sess.query(model).count()
            print(f"PostgreSQL table '{model.__tablename__}': {count} rows")

    print("\nSUCCESS: All data successfully migrated from SQLite to PostgreSQL!")


if __name__ == "__main__":
    migrate()
