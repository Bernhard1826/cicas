"""
Update orchestrator - coordinates the entire update process
"""
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from pathlib import Path

from app.models.models import Standard, Rule, UpdateLog, StandardRelationship
from app.services.crawlers.rfc_crawler import RFCCrawler
from app.services.crawlers.cabf_crawler import CABFCrawler
from app.services.crawlers.browser_ca_crawler import BrowserCACrawler
from app.services.crawlers.etsi_crawler import ETSICrawler
from app.services.full_pipeline_extractor import FullPipelineExtractor
from app.core.logging_config import app_logger
from app.core.config import settings
from app.core.database import get_db_context


class UpdateOrchestrator:
    """Orchestrates the complete update workflow"""

    def __init__(self, db: Session):
        self.db = db
        # 使用7层完整提取器（无需progress_callback，后台任务不需要实时进度）
        self.extractor = FullPipelineExtractor(db=db, progress_callback=None)

    @staticmethod
    def _clean_version_string(version: Optional[str]) -> Optional[str]:
        """
        Clean version string by removing trailing dots and whitespace

        Args:
            version: Raw version string

        Returns:
            Cleaned version string or None
        """
        if not version or version == "Unknown":
            return version

        # Remove trailing dots and whitespace
        cleaned = version.strip().rstrip('.')

        # Remove leading 'v' or 'V' if present
        if cleaned.lower().startswith('v'):
            cleaned = cleaned[1:].lstrip('. ')

        return cleaned if cleaned else None

    async def run_crawl(
        self,
        sources: Optional[List[str]] = None,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        爬取文档

        Args:
            sources: List of sources to update (None = all)
            force: Force update even if no changes

        Returns:
            Crawl summary
        """
        start_time = datetime.now()
        app_logger.info("Starting document crawl only (no rule extraction)")

        # Create update log
        update_log = UpdateLog(
            operation="crawl_only",
            status="started",
            message=f"Crawling sources: {sources or 'all'}"
        )
        self.db.add(update_log)
        self.db.commit()

        try:
            # Default to all sources
            if not sources:
                sources = ['RFC', 'CABF', 'Browser_CA', 'ETSI']

            summary = {
                'phase': 'crawling',
                'sources_processed': [],
                'texts_crawled': 0,
                'errors': []
            }

            # Crawl raw text only
            app_logger.info("Crawling raw text from standards...")

            for source in sources:
                try:
                    result = await self._crawl_source_text(source, force)
                    summary['sources_processed'].append({
                        'source': source,
                        'phase': 'crawling',
                        'status': 'success',
                        **result
                    })
                    summary['texts_crawled'] += result.get('texts_crawled', 0)

                except Exception as e:
                    app_logger.error(f"Error crawling source {source}: {e}")
                    summary['errors'].append(f"{source} crawling: {str(e)}")
                    summary['sources_processed'].append({
                        'source': source,
                        'phase': 'crawling',
                        'status': 'failed',
                        'error': str(e)
                    })

            # Update log with results
            execution_time = (datetime.now() - start_time).total_seconds()
            update_log.status = "completed" if not summary['errors'] else "completed_with_errors"
            update_log.rules_added = 0
            update_log.rules_updated = 0
            update_log.errors_count = len(summary['errors'])
            update_log.execution_time = execution_time
            update_log.completed_at = datetime.now()
            self.db.commit()

            app_logger.info(
                f"Crawl completed in {execution_time:.2f}s: "
                f"{summary['texts_crawled']} texts crawled"
            )

            return summary

        except Exception as e:
            app_logger.error(f"Fatal error in crawl process: {e}")
            update_log.status = "failed"
            update_log.message = str(e)
            update_log.completed_at = datetime.now()
            self.db.commit()
            raise

    async def run_full_update(
        self,
        sources: Optional[List[str]] = None,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Run complete update process with two phases:
        Phase 1: Crawl raw text from standards
        Phase 2: Use RAG+LLM to extract structured rules

        Args:
            sources: List of sources to update (None = all)
            force: Force update even if no changes

        Returns:
            Update summary
        """
        start_time = datetime.now()
        app_logger.info("Starting two-phase update process")

        # Create update log
        update_log = UpdateLog(
            operation="full_update",
            status="started",
            message=f"Updating sources: {sources or 'all'}"
        )
        self.db.add(update_log)
        self.db.commit()

        try:
            # Default to all sources
            if not sources:
                sources = ['RFC', 'CABF', 'Browser_CA', 'ETSI']

            summary = {
                'phase': 'crawling',
                'sources_processed': [],
                'texts_crawled': 0,
                'total_rules_added': 0,
                'total_rules_updated': 0,
                'total_rules_deprecated': 0,
                'errors': []
            }

            # ========== PHASE 1: Crawl raw text ==========
            app_logger.info("Phase 1: Crawling raw text from standards...")

            crawled_standards = []
            for source in sources:
                try:
                    result = await self._crawl_source_text(source, force)
                    summary['sources_processed'].append({
                        'source': source,
                        'phase': 'crawling',
                        'status': 'success',
                        **result
                    })
                    summary['texts_crawled'] += result.get('texts_crawled', 0)
                    crawled_standards.extend(result.get('standards', []))

                except Exception as e:
                    app_logger.error(f"Error crawling source {source}: {e}")
                    summary['errors'].append(f"{source} crawling: {str(e)}")
                    summary['sources_processed'].append({
                        'source': source,
                        'phase': 'crawling',
                        'status': 'failed',
                        'error': str(e)
                    })

            app_logger.info(f"Phase 1 completed: {summary['texts_crawled']} texts crawled")

            # ========== PHASE 2: RAG+LLM rule extraction ==========
            app_logger.info("Phase 2: Using RAG+LLM to extract rules...")
            summary['phase'] = 'parsing'

            for standard in crawled_standards:
                try:
                    result = await self._extract_rules_with_rag(standard)
                    summary['total_rules_added'] += result.get('rules_added', 0)
                    summary['total_rules_updated'] += result.get('rules_updated', 0)

                except Exception as e:
                    app_logger.error(f"Error extracting rules from standard {standard.id}: {e}")
                    summary['errors'].append(f"Standard {standard.id} parsing: {str(e)}")

            app_logger.info(f"Phase 2 completed: {summary['total_rules_added']} rules extracted")

            # Update log with results
            execution_time = (datetime.now() - start_time).total_seconds()
            update_log.status = "completed" if not summary['errors'] else "completed_with_errors"
            update_log.rules_added = summary['total_rules_added']
            update_log.rules_updated = summary['total_rules_updated']
            update_log.errors_count = len(summary['errors'])
            update_log.execution_time = execution_time
            update_log.completed_at = datetime.now()
            self.db.commit()

            app_logger.info(
                f"Update completed in {execution_time:.2f}s: "
                f"{summary['texts_crawled']} texts crawled, "
                f"{summary['total_rules_added']} rules added"
            )

            return summary

        except Exception as e:
            app_logger.error(f"Fatal error in update process: {e}")
            update_log.status = "failed"
            update_log.message = str(e)
            update_log.completed_at = datetime.now()
            self.db.commit()
            raise

    async def _crawl_source_text(self, source: str, force: bool = False) -> Dict[str, Any]:
        """
        Phase 1: Crawl raw text from source
        Only downloads and saves the text without parsing

        Args:
            source: Source name
            force: Force update

        Returns:
            Crawl result with standards list
        """
        app_logger.info(f"Crawling text from source: {source}")

        if source == 'RFC':
            return await self._crawl_rfc_text()
        elif source == 'CABF':
            return await self._crawl_cabf_text()
        elif source == 'Browser_CA':
            return await self._crawl_browser_ca_text()
        elif source == 'ETSI':
            return await self._crawl_etsi_text()
        else:
            raise ValueError(f"Unknown source: {source}")

    async def _crawl_rfc_text(self) -> Dict[str, Any]:
        """Crawl RFC documents (text only)"""
        async with RFCCrawler() as crawler:
            rfc_data_list = await crawler.crawl_all_default_rfcs()

        standards = []
        texts_crawled = 0

        for rfc_data in rfc_data_list:
            try:
                # Check if standard already exists
                existing = self.db.query(Standard).filter(
                    Standard.source == "RFC",
                    Standard.file_hash == rfc_data['file_hash']
                ).first()

                if existing:
                    app_logger.info(f"RFC {rfc_data['rfc_number']} unchanged, skipping")
                    continue

                # Create standard record (text only, no rules yet)
                import json

                # Prepare metadata for JSON serialization (convert datetime to string)
                metadata = rfc_data.get('metadata', {}).copy()
                for key, value in metadata.items():
                    if isinstance(value, datetime):
                        metadata[key] = value.isoformat()

                standard = Standard(
                    source="RFC",
                    title=rfc_data['title'],
                    version=str(rfc_data['rfc_number']),
                    publish_date=rfc_data.get('publish_date'),
                    document_last_updated=rfc_data.get('document_last_updated') or rfc_data.get('publish_date'),
                    url=rfc_data['url'],
                    file_path=rfc_data['file_path'],
                    file_hash=rfc_data['file_hash'],
                    metadata_json=json.dumps(metadata),
                    is_latest=True if not (rfc_data.get('metadata', {}).get('obsoleted_by')) else False
                )
                self.db.add(standard)
                self.db.commit()

                app_logger.info(f"Crawled RFC {rfc_data['rfc_number']}: {rfc_data['title']}")
                standards.append(standard)
                texts_crawled += 1

            except Exception as e:
                app_logger.error(f"Error crawling RFC {rfc_data.get('rfc_number')}: {e}")
                continue

        return {
            'texts_crawled': texts_crawled,
            'standards': standards
        }

    async def _crawl_cabf_text(self) -> Dict[str, Any]:
        """Crawl CA/B Forum documents (latest version only, deletes old versions)"""
        async with CABFCrawler() as crawler:
            cabf_data_list = await crawler.crawl_all_cabf_documents()

        standards = []
        texts_crawled = 0
        old_versions_deleted = 0

        for cabf_data in cabf_data_list:
            try:
                # Clean version string before storing
                clean_version = self._clean_version_string(cabf_data.get('version'))
                url = cabf_data['url']
                file_path = cabf_data['file_path']
                source = cabf_data["source"]
                title = cabf_data['title']

                # ========== Check if this exact version already exists ==========
                existing_by_hash = self.db.query(Standard).filter(
                    Standard.file_hash == cabf_data['file_hash']
                ).first()

                if existing_by_hash:
                    app_logger.info(
                        f"Document already exists (same hash): {title} v{clean_version} "
                        f"(existing ID: {existing_by_hash.id})"
                    )
                    continue

                # ========== Delete old versions of the same standard ==========
                # Find all old versions: same source and title, but different version
                # Also handle source naming variations (CABF-Server vs CABF_SERVER)
                source_variations = [source]
                if source == "CABF-Server":
                    source_variations.append("CABF_SERVER")
                elif source == "CABF_SERVER":
                    source_variations.append("CABF-Server")
                elif source == "CABF-EV":
                    source_variations.append("CABF_EV")
                elif source == "CABF_EV":
                    source_variations.append("CABF-EV")
                elif source == "CABF-S/MIME":
                    source_variations.append("CABF_SMIME")
                elif source == "CABF_SMIME":
                    source_variations.append("CABF-S/MIME")
                elif source == "CABF-NetSec":
                    source_variations.append("CABF_NETSEC")
                elif source == "CABF_NETSEC":
                    source_variations.append("CABF-NetSec")
                elif source == "CABF-CS":
                    source_variations.append("CABF_CS")
                elif source == "CABF_CS":
                    source_variations.append("CABF-CS")

                old_standards = self.db.query(Standard).filter(
                    Standard.source.in_(source_variations),
                    Standard.title == title
                ).all()

                for old_std in old_standards:
                    app_logger.info(
                        f"Deleting old version: {old_std.source} - {old_std.title[:60]} "
                        f"v{old_std.version} (ID: {old_std.id})"
                    )

                    # Delete StandardRelationships first (both source and target)
                    relationships_deleted = self.db.query(StandardRelationship).filter(
                        (StandardRelationship.source_standard_id == old_std.id) |
                        (StandardRelationship.target_standard_id == old_std.id)
                    ).delete(synchronize_session=False)

                    if relationships_deleted > 0:
                        app_logger.info(f"Deleted {relationships_deleted} standard relationships")

                    # Delete associated rules
                    rules_deleted = self.db.query(Rule).filter(
                        Rule.standard_id == old_std.id
                    ).delete()

                    if rules_deleted > 0:
                        app_logger.info(f"Deleted {rules_deleted} associated rules")

                    # Delete local file if it exists
                    if old_std.file_path:
                        old_file_path = Path(settings.data_raw_path) / old_std.file_path
                        if old_file_path.exists():
                            try:
                                old_file_path.unlink()
                                app_logger.info(f"Deleted old file: {old_file_path}")
                            except Exception as e:
                                app_logger.warning(f"Failed to delete old file {old_file_path}: {e}")

                    # Delete standard record
                    self.db.delete(old_std)
                    old_versions_deleted += 1

                self.db.commit()

                # Save new version
                standard = Standard(
                    source=source,
                    title=title,
                    version=clean_version,
                    publish_date=cabf_data.get('publish_date'),
                    document_last_updated=cabf_data.get('document_last_updated') or cabf_data.get('publish_date'),
                    url=url,
                    file_path=file_path,
                    file_hash=cabf_data['file_hash'],
                    is_latest=True  # Always true since we only crawl latest
                )
                self.db.add(standard)
                self.db.commit()

                app_logger.info(
                    f"Saved latest CABF doc: {source} - {title[:60]} v{clean_version}"
                )
                standards.append(standard)
                texts_crawled += 1

            except Exception as e:
                app_logger.error(f"Error crawling CABF doc: {e}")
                self.db.rollback()
                continue

        app_logger.info(f"CABF crawl complete: {texts_crawled} latest versions saved, {old_versions_deleted} old versions deleted")

        return {
            'texts_crawled': texts_crawled,
            'old_versions_deleted': old_versions_deleted,
            'standards': standards
        }

    async def _crawl_browser_ca_text(self) -> Dict[str, Any]:
        """Crawl browser CA policies (all versions)"""
        async with BrowserCACrawler() as crawler:
            browser_data_list = await crawler.crawl_all_browser_policies()

        standards = []
        texts_crawled = 0

        for browser_data in browser_data_list:
            try:
                url = browser_data['url']
                source = browser_data['source']
                title = browser_data['title']
                version = browser_data.get('version')

                # ========== 去重逻辑 ==========
                # 1. 检查是否已存在：(source, url) 组合唯一
                existing_by_url = self.db.query(Standard).filter(
                    Standard.source == source,
                    Standard.url == url
                ).first()

                if existing_by_url:
                    app_logger.info(f"Browser CA policy already exists (same URL): {url}")
                    continue

                # 2. 检查是否已存在：(source, title, version) 组合唯一
                if title and version:
                    existing_by_version = self.db.query(Standard).filter(
                        Standard.source == source,
                        Standard.title == title,
                        Standard.version == version
                    ).first()

                    if existing_by_version:
                        app_logger.info(f"Browser CA policy already exists (same title+version): {title} v{version}")
                        continue

                standard = Standard(
                    source=source,
                    title=title,
                    url=url,
                    file_path=browser_data['file_path'],
                    file_hash=browser_data['content_hash'],
                    publish_date=browser_data.get('publish_date'),
                    document_last_updated=browser_data.get('document_last_updated') or browser_data.get('publish_date'),
                    version=version,
                    is_latest=browser_data.get('is_latest', True)
                )
                self.db.add(standard)
                self.db.commit()

                app_logger.info(f"Crawled browser CA: {browser_data['browser']} (is_latest={browser_data.get('is_latest', True)})")
                standards.append(standard)
                texts_crawled += 1

            except Exception as e:
                app_logger.error(f"Error crawling browser CA: {e}")
                continue

        return {
            'texts_crawled': texts_crawled,
            'standards': standards
        }

    async def _crawl_etsi_text(self) -> Dict[str, Any]:
        """Crawl ETSI standards (latest version only, deletes old versions)"""
        async with ETSICrawler() as crawler:
            etsi_data_list = await crawler.crawl_all_default_standards()

        standards = []
        texts_crawled = 0
        old_versions_deleted = 0

        for etsi_data in etsi_data_list:
            try:
                title = etsi_data['title']
                version = etsi_data.get('version')
                standard_id = etsi_data.get('standard_id', '')

                # Check if this exact version already exists
                existing = self.db.query(Standard).filter(
                    Standard.source == "ETSI",
                    Standard.file_hash == etsi_data['file_hash']
                ).first()

                if existing:
                    app_logger.info(f"ETSI {standard_id} v{version} unchanged, skipping")
                    continue

                # ========== Delete old versions of the same standard ==========
                # Convert standard_id (EN_319_412-2) to title prefix pattern (EN 319 412-2)
                # This allows matching old versions regardless of version number in title
                title_prefix = standard_id.replace('_', ' ')  # EN_319_412-2 -> EN 319 412-2

                # Find all old versions using LIKE match on title prefix
                old_standards = self.db.query(Standard).filter(
                    Standard.source == "ETSI",
                    Standard.title.like(f"{title_prefix}%")
                ).all()

                for old_std in old_standards:
                    app_logger.info(
                        f"Deleting old ETSI version: {old_std.title[:60]} "
                        f"v{old_std.version} (ID: {old_std.id})"
                    )

                    # Delete associated rules first
                    rules_deleted = self.db.query(Rule).filter(
                        Rule.standard_id == old_std.id
                    ).delete()

                    if rules_deleted > 0:
                        app_logger.info(f"Deleted {rules_deleted} associated rules")

                    # Delete local file if it exists
                    if old_std.file_path:
                        old_file_path = Path(settings.data_raw_path) / old_std.file_path
                        if old_file_path.exists():
                            try:
                                old_file_path.unlink()
                                app_logger.info(f"Deleted old file: {old_file_path}")
                            except Exception as e:
                                app_logger.warning(f"Failed to delete old file {old_file_path}: {e}")

                    # Delete standard record
                    self.db.delete(old_std)
                    old_versions_deleted += 1

                self.db.commit()

                # Save new version
                standard = Standard(
                    source="ETSI",
                    title=title,
                    version=version,
                    publish_date=etsi_data.get('publish_date'),
                    document_last_updated=etsi_data.get('document_last_updated') or etsi_data.get('publish_date'),
                    url=etsi_data['url'],
                    file_path=etsi_data['file_path'],
                    file_hash=etsi_data['file_hash'],
                    is_latest=True  # Always true since we only crawl latest
                )
                self.db.add(standard)
                self.db.commit()

                app_logger.info(f"Saved latest ETSI: {standard_id} - {title[:60]} v{version}")
                standards.append(standard)
                texts_crawled += 1

            except Exception as e:
                app_logger.error(f"Error crawling ETSI standard: {e}")
                self.db.rollback()
                continue

        app_logger.info(f"ETSI crawl complete: {texts_crawled} latest versions saved, {old_versions_deleted} old versions deleted")

        return {
            'texts_crawled': texts_crawled,
            'old_versions_deleted': old_versions_deleted,
            'standards': standards
        }

    async def _extract_rules_with_rag(self, standard: Standard) -> Dict[str, Any]:
        """
        Phase 2: Extract rules using 7-layer FullPipelineExtractor

        Args:
            standard: Standard object with file saved to database

        Returns:
            Extraction result
        """
        app_logger.info(f"Extracting rules from standard: {standard.title} using 7-Layer Full Pipeline")

        try:
            # 使用7层完整提取器（Regex + RAG + LLM + 元信息过滤 + 去重 + KG + 证据验证）
            result = await self.extractor.extract_with_full_pipeline(standard.id)

            # 从result中获取最终规则并保存到数据库
            final_rules = result.get('final_rules', [])
            resolved_irs = result.get('resolved_irs', [])

            app_logger.info(f"Extracted {len(final_rules)} rules from {standard.title}, saving to database...")

            # Save rules to database using raw SQL to avoid ORM type conflicts
            import hashlib
            import json
            from sqlalchemy import text as sql_text

            rules_added = 0
            rules_skipped = 0
            ir_saved = 0
            for idx, rule_dict in enumerate(final_rules):
                text_content = rule_dict.get('rule_text', rule_dict.get('text', ''))
                rule_hash = rule_dict.get('rule_hash') or rule_dict.get('hash')
                if not rule_hash:
                    rule_hash = hashlib.sha256(text_content.encode('utf-8')).hexdigest()

                ir_json = None
                ir_obj = None
                if idx < len(resolved_irs):
                    ir_obj = resolved_irs[idx]
                    try:
                        ir_json = ir_obj.to_json() if hasattr(ir_obj, 'to_json') else json.dumps(ir_obj, ensure_ascii=False)
                    except Exception as e:
                        app_logger.warning(f"Failed to serialize IR for rule idx={idx}, hash={rule_hash[:16]}...: {e}")

                lintable = None
                obligation = rule_dict.get('obligation')
                subject = None
                if ir_json:
                    try:
                        ir_payload = json.loads(ir_json)
                        ir_core = ir_payload.get('ir', ir_payload)
                        lintable = ir_core.get('lintable')
                        obligation = ir_core.get('obligation') or obligation
                        subject = ir_core.get('subject')
                    except Exception as e:
                        app_logger.warning(f"Failed to parse serialized IR for rule idx={idx}, hash={rule_hash[:16]}...: {e}")

                subject_role = None
                if isinstance(subject, dict):
                    subject_role = subject.get('raw') or subject.get('path') or subject.get('field_id')
                elif subject is not None:
                    subject_role = str(subject)

                rule_category = None
                if lintable is True:
                    rule_category = 'lintable'
                elif lintable is False:
                    rule_category = 'non_lintable'

                # Use raw SQL UPSERT so reruns can backfill IR metadata onto existing rows
                result = self.db.execute(
                    sql_text("""
                        INSERT INTO rules (
                            standard_id, section, text, rule_type, hash, origin,
                            ir_data, rule_category
                        )
                        VALUES (
                            :standard_id, :section, :text, :rule_type, :hash, 'source',
                            :ir_data, :rule_category
                        )
                        ON CONFLICT (standard_id, hash) DO UPDATE SET
                            section = COALESCE(rules.section, EXCLUDED.section),
                            text = COALESCE(NULLIF(rules.text, ''), EXCLUDED.text),
                            rule_type = COALESCE(rules.rule_type, EXCLUDED.rule_type),
                            ir_data = COALESCE(rules.ir_data, EXCLUDED.ir_data),
                            rule_category = COALESCE(rules.rule_category, EXCLUDED.rule_category)
                    """),
                    {
                        'standard_id': standard.id,
                        'section': rule_dict.get('section'),
                        'text': text_content,
                        'rule_type': obligation,
                        'hash': rule_hash,
                        'ir_data': ir_json,
                        'rule_category': rule_category
                    }
                )
                if result.rowcount > 0:
                    if ir_json:
                        ir_saved += 1
                    if idx >= len(resolved_irs):
                        rules_skipped += 1
                    else:
                        rules_added += 1
                else:
                    rules_skipped += 1

            self.db.commit()
            app_logger.info(
                f"Successfully saved/backfilled {rules_added} rules to database "
                f"({rules_skipped} without IR or unchanged, IR saved for {ir_saved} rules)"
            )

            return {
                'rules_added': rules_added,
                'rules_updated': 0
            }

        except Exception as e:
            self.db.rollback()
            app_logger.error(f"Error extracting rules: {e}")
            import traceback
            traceback.print_exc()
            return {'rules_added': 0, 'rules_updated': 0}

    async def _update_source(self, source: str, force: bool = False) -> Dict[str, Any]:
        """
        Update a specific source

        Args:
            source: Source name
            force: Force update

        Returns:
            Update result
        """
        app_logger.info(f"Updating source: {source}")

        if source == 'RFC':
            return await self._update_rfc_source()
        elif source == 'CABF':
            return await self._update_cabf_source()
        elif source == 'Browser_CA':
            return await self._update_browser_ca_source()
        elif source == 'ETSI':
            return await self._update_etsi_source()
        else:
            raise ValueError(f"Unknown source: {source}")

    async def _update_rfc_source(self) -> Dict[str, Any]:
        """Update RFC documents"""
        async with RFCCrawler() as crawler:
            # Crawl all default RFCs
            rfc_data_list = await crawler.crawl_all_default_rfcs()

        rules_added = 0
        rules_updated = 0

        for rfc_data in rfc_data_list:
            try:
                # Check if standard already exists
                existing = self.db.query(Standard).filter(
                    Standard.source == "RFC",
                    Standard.file_hash == rfc_data['file_hash']
                ).first()

                if existing:
                    app_logger.info(f"RFC {rfc_data['rfc_number']} unchanged, skipping")
                    continue

                # Create standard record
                standard = Standard(
                    source="RFC",
                    title=rfc_data['title'],
                    version=str(rfc_data['rfc_number']),
                    publish_date=rfc_data.get('publish_date'),
                    url=rfc_data['url'],
                    file_path=rfc_data['file_path'],
                    file_hash=rfc_data['file_hash'],
                    is_latest=True
                )
                self.db.add(standard)
                self.db.commit()

                # Parse RFC and extract rules
                rules = self.rfc_parser.parse_rfc(Path(rfc_data['file_path']))

                # Process rules
                new_rules = await self._process_rules(rules, standard.id)
                rules_added += new_rules

            except Exception as e:
                app_logger.error(f"Error processing RFC {rfc_data.get('rfc_number')}: {e}")
                continue

        return {
            'rules_added': rules_added,
            'rules_updated': rules_updated
        }

    async def _update_cabf_source(self) -> Dict[str, Any]:
        """Update CA/B Forum documents"""
        async with CABFCrawler() as crawler:
            cabf_data_list = await crawler.crawl_all_cabf_documents()

        rules_added = 0

        for cabf_data in cabf_data_list:
            try:
                # Check if standard exists
                existing = self.db.query(Standard).filter(
                    Standard.source == cabf_data["source"],
                    Standard.file_hash == cabf_data['file_hash']
                ).first()

                if existing:
                    continue

                # Create standard record
                standard = Standard(
                    source=cabf_data["source"],
                    title=cabf_data['title'],
                    version=cabf_data.get('version'),
                    publish_date=cabf_data.get('publish_date'),
                    document_last_updated=cabf_data.get('document_last_updated') or cabf_data.get('publish_date'),
                    url=cabf_data['url'],
                    file_path=cabf_data['file_path'],
                    file_hash=cabf_data['file_hash'],
                    is_latest=True
                )
                self.db.add(standard)
                self.db.commit()

                # Parse PDF and extract rules
                rules = self.pdf_parser.parse_pdf(Path(cabf_data['file_path']))

                # Process rules
                new_rules = await self._process_rules(rules, standard.id)
                rules_added += new_rules

            except Exception as e:
                app_logger.error(f"Error processing CABF doc: {e}")
                continue

        return {
            'rules_added': rules_added,
            'rules_updated': 0
        }

    async def _update_browser_ca_source(self) -> Dict[str, Any]:
        """Update browser CA policies"""
        async with BrowserCACrawler() as crawler:
            browser_data_list = await crawler.crawl_all_browser_policies()

        rules_added = 0

        for browser_data in browser_data_list:
            try:
                # Create standard record
                standard = Standard(
                    source=browser_data['source'],
                    title=browser_data['title'],
                    version=browser_data.get('version'),
                    publish_date=browser_data.get('publish_date'),
                    effective_date=browser_data.get('effective_date'),
                    document_last_updated=browser_data.get('document_last_updated'),
                    url=browser_data['url'],
                    file_path=browser_data['file_path'],
                    file_hash=browser_data['content_hash'],
                    is_latest=True
                )
                self.db.add(standard)
                self.db.commit()

                app_logger.info(f"Added browser CA policy: {browser_data['browser']}")

            except Exception as e:
                app_logger.error(f"Error processing browser CA: {e}")
                continue

        return {
            'rules_added': rules_added,
            'rules_updated': 0
        }

    async def _update_etsi_source(self) -> Dict[str, Any]:
        """Update ETSI standards"""
        async with ETSICrawler() as crawler:
            etsi_data_list = await crawler.crawl_all_default_standards()

        rules_added = 0

        for etsi_data in etsi_data_list:
            try:
                # Check if standard exists
                existing = self.db.query(Standard).filter(
                    Standard.source == "ETSI",
                    Standard.file_hash == etsi_data['file_hash']
                ).first()

                if existing:
                    app_logger.info(f"ETSI {etsi_data['standard_id']} unchanged, skipping")
                    continue

                # Create standard record
                standard = Standard(
                    source="ETSI",
                    title=etsi_data['title'],
                    version=etsi_data.get('version'),
                    publish_date=etsi_data.get('publish_date'),
                    document_last_updated=etsi_data.get('document_last_updated') or etsi_data.get('publish_date'),
                    url=etsi_data['url'],
                    file_path=etsi_data['file_path'],
                    file_hash=etsi_data['file_hash'],
                    is_latest=True
                )
                self.db.add(standard)
                self.db.commit()

                # Parse ETSI PDF and extract rules using intelligent parser
                from app.services.parsers.intelligent_parser import IntelligentRuleParser

                intelligent_parser = IntelligentRuleParser()

                # For ETSI PDFs, we need to extract text first
                # Using the existing PDF parser
                rules = self.pdf_parser.parse_pdf(Path(etsi_data['file_path']))

                # If PDF parser didn't extract enough rules, use intelligent parser
                if len(rules) < 5 and etsi_data.get('abstract'):
                    # Use intelligent parser on the abstract/metadata
                    app_logger.info(f"Using intelligent parser for ETSI {etsi_data['standard_id']}")
                    source_context = {
                        'source': 'ETSI',
                        'title': etsi_data['title'],
                        'standard_id': etsi_data['standard_id']
                    }
                    # Parse available text
                    text_to_parse = etsi_data.get('abstract', '')
                    if text_to_parse:
                        additional_rules = await intelligent_parser.parse_document(
                            text_to_parse,
                            source_context,
                            use_llm=True
                        )
                        rules.extend(additional_rules)

                # Process rules
                new_rules = await self._process_rules(rules, standard.id)
                rules_added += new_rules

                app_logger.info(f"Processed ETSI {etsi_data['standard_id']}: {new_rules} rules added")

            except Exception as e:
                app_logger.error(f"Error processing ETSI standard: {e}")
                import traceback
                traceback.print_exc()
                continue

        return {
            'rules_added': rules_added,
            'rules_updated': 0
        }

    async def _process_rules(
        self,
        rules: List[Dict[str, Any]],
        standard_id: int
    ) -> int:
        """
        Process and store rules

        Args:
            rules: List of rule dictionaries
            standard_id: Standard ID

        Returns:
            Number of rules added
        """
        if not rules:
            return 0

        added_count = 0

        for rule_data in rules:
            try:
                # Add standard_id
                rule_data['standard_id'] = standard_id

                # Generate hash if not present
                if 'hash' not in rule_data:
                    rule_text = f"{rule_data.get('section', '')}{rule_data.get('text', '')}"
                    import hashlib
                    rule_data['hash'] = hashlib.sha256(rule_text.encode('utf-8')).hexdigest()

                # Check if rule already exists
                existing = self.db.query(Rule).filter(
                    Rule.hash == rule_data['hash']
                ).first()

                if existing:
                    app_logger.debug(f"Rule already exists, skipping: {rule_data.get('text', '')[:50]}")
                    continue

                # Create rule record
                # 注意：section只存储章节号（如"7.1.2.11.4"），不包含文档名称
                # 文档名称通过standard_id关联获取
                rule = Rule(
                    standard_id=rule_data['standard_id'],
                    section=rule_data.get('section', ''),
                    subsection=rule_data.get('subsection'),
                    title=rule_data.get('title'),
                    text=rule_data.get('text'),
                    rule_type=rule_data.get('rule_type'),
                    context=rule_data.get('context'),
                    hash=rule_data['hash']
                )

                self.db.add(rule)
                added_count += 1

            except Exception as e:
                app_logger.error(f"Error processing rule: {e}")
                continue

        self.db.commit()

        app_logger.info(f"Added {added_count} rules for standard {standard_id}")

        return added_count
