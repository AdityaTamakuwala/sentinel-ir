"""Declarative YAML playbook loader and database synchronization service."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.automation import Playbook, PlaybookVersion
from app.schemas.playbook import PlaybookDefinition

logger = logging.getLogger("sentinel.playbook.loader")

def get_default_playbooks_dir() -> Path:
    candidates = [
        Path("/app/playbooks"),
        Path(__file__).resolve().parent.parent.parent.parent.parent / "playbooks",
        Path(__file__).resolve().parent.parent.parent.parent / "playbooks",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return candidates[1]


DEFAULT_PLAYBOOKS_DIR = get_default_playbooks_dir()


class PlaybookLoader:
    """Service to load, validate, and synchronize YAML playbook definitions."""

    @staticmethod
    def parse_yaml_definition(yaml_content: str) -> tuple[PlaybookDefinition, dict[str, Any]]:
        """Parse raw YAML string into validated PlaybookDefinition and raw dict."""
        parsed = yaml.safe_load(yaml_content)
        if not isinstance(parsed, dict):
            raise ValueError("Playbook definition YAML must be a top-level dictionary")
        definition = PlaybookDefinition.model_validate(parsed)
        return definition, parsed

    @classmethod
    def load_from_file(cls, file_path: Path) -> tuple[PlaybookDefinition, str, dict[str, Any]]:
        """Load and validate playbook from a YAML file path."""
        content = file_path.read_text(encoding="utf-8")
        definition, raw_dict = cls.parse_yaml_definition(content)
        return definition, content, raw_dict

    @classmethod
    async def sync_builtin_playbooks(
        cls,
        session: AsyncSession,
        playbooks_dir: Path | None = None,
    ) -> list[Playbook]:
        """Synchronize all YAML playbooks from the filesystem into the database."""
        target_dir = playbooks_dir or DEFAULT_PLAYBOOKS_DIR
        if not target_dir.exists():
            logger.warning("Playbooks directory not found: %s", target_dir)
            return []

        synced_playbooks: list[Playbook] = []
        yaml_files = sorted(target_dir.glob("*.yaml")) + sorted(target_dir.glob("*.yml"))

        for file_path in yaml_files:
            try:
                definition, raw_yaml, raw_dict = cls.load_from_file(file_path)
                slug = definition.slug

                # Check if playbook exists
                stmt = select(Playbook).where(Playbook.slug == slug)
                result = await session.execute(stmt)
                playbook = result.scalar_one_or_none()

                if not playbook:
                    playbook = Playbook(
                        slug=slug,
                        name=definition.name,
                        description=definition.description,
                        is_enabled=True,
                        auto_trigger_mode="propose",
                        current_version=definition.version,
                        is_builtin=True,
                    )
                    session.add(playbook)
                    await session.flush()
                    logger.info("Created new builtin playbook: %s (%s)", definition.name, slug)
                else:
                    playbook.name = definition.name
                    playbook.description = definition.description
                    playbook.current_version = definition.version
                    playbook.is_builtin = True
                    await session.flush()

                # Sync PlaybookVersion
                v_stmt = select(PlaybookVersion).where(
                    PlaybookVersion.playbook_id == playbook.id,
                    PlaybookVersion.version == definition.version,
                )
                v_res = await session.execute(v_stmt)
                p_version = v_res.scalar_one_or_none()

                if not p_version:
                    p_version = PlaybookVersion(
                        playbook_id=playbook.id,
                        version=definition.version,
                        definition_yaml=raw_yaml,
                        definition_json=raw_dict,
                        trigger_config=definition.triggers,
                        input_schema=definition.parameters,
                    )
                    session.add(p_version)
                    await session.flush()
                    logger.info("Registered version %d for playbook %s", definition.version, slug)
                else:
                    p_version.definition_yaml = raw_yaml
                    p_version.definition_json = raw_dict
                    p_version.trigger_config = definition.triggers
                    p_version.input_schema = definition.parameters
                    await session.flush()

                synced_playbooks.append(playbook)

            except Exception as exc:
                logger.error("Failed to load playbook from %s: %s", file_path, exc, exc_info=True)

        await session.commit()
        return synced_playbooks
