"""Every revision declares `expand_only` (Tyyni convention); the template enforces it."""

import ast
import re
import shutil
from pathlib import Path

from alembic import command
from alembic.config import Config

from tests.conftest import REPO_ROOT

VERSIONS = REPO_ROOT / "migrations" / "versions"


def expand_only_declarations(source: str) -> list[object]:
    """Values of module-level `expand_only = <literal>` assignments, plus any other binding."""
    found: list[object] = []
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if "expand_only" in names:
                ok = len(node.targets) == 1 and isinstance(node.value, ast.Constant)
                found.append(node.value.value if ok else "malformed")  # type: ignore[union-attr]
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id == "expand_only":
                found.append("malformed")
    return found


def test_every_revision_declares_expand_only() -> None:
    bad = [
        path.name
        for path in sorted(VERSIONS.glob("*.py"))
        if not (
            len(decl := expand_only_declarations(path.read_text())) == 1
            and isinstance(decl[0], bool)
        )
    ]
    assert not bad, f"need exactly one module-level `expand_only = True|False`: {bad}"


def test_declaration_parser_rejects_malformed_forms() -> None:
    assert expand_only_declarations("expand_only = True\n") == [True]
    assert expand_only_declarations("x = 1\n") == []
    assert expand_only_declarations("expand_only: bool = True\n") == ["malformed"]
    assert expand_only_declarations("expand_only = bool(1)\n") == ["malformed"]
    assert expand_only_declarations("expand_only = True\nexpand_only = False\n") == [True, False]


def test_new_revision_template_declares_expand_only_false(tmp_path: Path) -> None:
    script_dir = tmp_path / "migrations"
    shutil.copytree(REPO_ROOT / "migrations", script_dir, ignore=shutil.ignore_patterns("*.py"))
    (script_dir / "versions").mkdir(exist_ok=True)
    cfg = Config()
    cfg.set_main_option("script_location", str(script_dir))
    cfg.set_main_option("file_template", "%%(year)d%%(month).2d%%(day).2d_%%(rev)s_%%(slug)s")
    command.revision(cfg, message="add example table", rev_id="0001")

    [generated] = list((script_dir / "versions").glob("*.py"))
    assert re.fullmatch(r"\d{8}_0001_add_example_table\.py", generated.name)
    assert expand_only_declarations(generated.read_text()) == [False]


def test_alembic_ini_uses_dated_file_template() -> None:
    ini = (REPO_ROOT / "alembic.ini").read_text()
    assert "file_template = %%(year)d%%(month).2d%%(day).2d_%%(rev)s_%%(slug)s" in ini
    assert re.search(r"^sqlalchemy\.url =\s*$", ini, re.MULTILINE)
