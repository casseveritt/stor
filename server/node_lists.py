"""Named node lists with optional boolean-expression definitions."""
import json
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import InternalOrOwnerDep as OwnerDep
from .db import now_ns

router = APIRouter(prefix="/node-lists")


# ── evaluation ────────────────────────────────────────────────────────────────

def _evaluate(db, list_id: str, visited: set | None = None) -> set[str]:
    """Recursively evaluate a list's expression into a flat set of node_ids."""
    if visited is None:
        visited = set()
    if list_id in visited:
        return set()
    visited.add(list_id)

    row = db.execute("SELECT expression FROM node_lists WHERE id = ?", (list_id,)).fetchone()
    if row is None:
        # Not a list — treat as a literal node_id.
        return {list_id}
    expression = json.loads(row[0]) if row[0] else None
    if expression is None:
        rows = db.execute(
            "SELECT node_id FROM node_list_members WHERE list_id = ?", (list_id,)
        ).fetchall()
        return {r[0] for r in rows}

    op = expression["op"]
    args = expression.get("args", [])
    sets = [_evaluate(db, arg_id, visited) for arg_id in args]
    if not sets:
        return set()

    result = sets[0]
    for s in sets[1:]:
        if op == "union":
            result = result | s
        elif op == "subtract":
            result = result - s
        elif op == "intersect":
            result = result & s
    return result


def _materialize(db, list_id: str) -> list[str]:
    """Evaluate expression, store flattened result, mark evaluated_at."""
    members = sorted(_evaluate(db, list_id))
    db.execute("DELETE FROM node_list_members WHERE list_id = ?", (list_id,))
    for node_id in members:
        db.execute(
            "INSERT OR IGNORE INTO node_list_members (list_id, node_id) VALUES (?, ?)",
            (list_id, node_id),
        )
    db.execute(
        "UPDATE node_lists SET evaluated_at = ? WHERE id = ?", (now_ns(), list_id)
    )
    db.commit()
    return members


def _invalidate_dependents(db, changed_list_id: str) -> None:
    """Mark all lists that (directly or transitively) depend on changed_list_id as stale."""
    frontier = {changed_list_id}
    invalidated: set[str] = set()
    all_expr = db.execute(
        "SELECT id, expression FROM node_lists WHERE expression IS NOT NULL"
    ).fetchall()
    while frontier:
        next_frontier: set[str] = set()
        for lid, expr_json in all_expr:
            if lid in invalidated or lid in frontier:
                continue
            try:
                args = json.loads(expr_json).get("args", [])
                if any(a in frontier for a in args):
                    next_frontier.add(lid)
                    invalidated.add(lid)
            except Exception:
                pass
        frontier = next_frontier

    if invalidated:
        ph = ",".join("?" * len(invalidated))
        db.execute(
            f"UPDATE node_lists SET evaluated_at = NULL WHERE id IN ({ph})",
            list(invalidated),
        )
        db.commit()


def _get_members(db, list_id: str) -> list[dict]:
    """Return flat member list, re-evaluating from expression if stale."""
    row = db.execute(
        "SELECT expression, evaluated_at FROM node_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        return []
    expression, evaluated_at = row
    if expression is not None and evaluated_at is None:
        _materialize(db, list_id)

    rows = db.execute(
        """SELECT m.node_id, u.name
           FROM node_list_members m LEFT JOIN users u ON u.node_id = m.node_id
           WHERE m.list_id = ?
           ORDER BY COALESCE(u.name, m.node_id)""",
        (list_id,),
    ).fetchall()
    return [{"node_id": r[0], "display_name": r[1] or r[0]} for r in rows]


def get_list_members_set(db, list_id: str) -> set[str]:
    """Return the flat member set for a list, evaluating if stale. Used by access checks."""
    row = db.execute(
        "SELECT expression, evaluated_at FROM node_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        return set()
    expression, evaluated_at = row
    if expression is not None and evaluated_at is None:
        _materialize(db, list_id)
    rows = db.execute(
        "SELECT node_id FROM node_list_members WHERE list_id = ?", (list_id,)
    ).fetchall()
    return {r[0] for r in rows}


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_node_lists(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute("""
        SELECT nl.id, nl.name, nl.expression, nl.evaluated_at, COUNT(m.node_id) AS member_count
        FROM node_lists nl LEFT JOIN node_list_members m ON m.list_id = nl.id
        GROUP BY nl.id
        ORDER BY nl.name
    """).fetchall()
    return {"lists": [
        {
            "id": r[0],
            "name": r[1],
            "expression": json.loads(r[2]) if r[2] else None,
            "stale": r[2] is not None and r[3] is None,
            "member_count": r[4],
        }
        for r in rows
    ]}


class _CreateListBody(BaseModel):
    name: str
    members: list[str] = []
    expression: dict | None = None


@router.post("", status_code=201)
def create_node_list(payload: _CreateListBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if not payload.name.strip():
        raise HTTPException(400, "name is required")
    list_id = str(uuid.uuid4())
    expr_json = json.dumps(payload.expression) if payload.expression else None
    db.execute(
        "INSERT INTO node_lists (id, name, expression, evaluated_at) VALUES (?, ?, ?, ?)",
        (list_id, payload.name.strip(), expr_json, None if expr_json else now_ns()),
    )
    if not expr_json:
        for node_id in payload.members:
            db.execute(
                "INSERT OR IGNORE INTO node_list_members (list_id, node_id) VALUES (?, ?)",
                (list_id, node_id),
            )
    db.commit()
    if expr_json:
        _materialize(db, list_id)
    return {
        "id": list_id,
        "name": payload.name.strip(),
        "expression": payload.expression,
        "stale": False,
        "members": _get_members(db, list_id),
    }


@router.get("/{list_id}")
def get_node_list(list_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = db.execute(
        "SELECT id, name, expression, evaluated_at FROM node_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(404, "List not found")
    lid, name, expr_json, evaluated_at = row
    expression = json.loads(expr_json) if expr_json else None
    return {
        "id": lid,
        "name": name,
        "expression": expression,
        "stale": expression is not None and evaluated_at is None,
        "members": _get_members(db, list_id),
    }


class _PatchListBody(BaseModel):
    name: str | None = None
    members: list[str] | None = None
    add_members: list[str] | None = None
    remove_members: list[str] | None = None
    expression: dict | None = None
    clear_expression: bool = False


@router.patch("/{list_id}")
def update_node_list(
    list_id: str, payload: _PatchListBody, request: Request, identity: OwnerDep
):
    db = request.app.state.db
    row = db.execute(
        "SELECT id, expression FROM node_lists WHERE id = ?", (list_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(404, "List not found")

    updates: list[str] = []
    params: list = []
    members_changed = False
    set_expression = False

    if payload.name is not None:
        if not payload.name.strip():
            raise HTTPException(400, "name cannot be empty")
        updates.append("name = ?")
        params.append(payload.name.strip())

    if payload.expression is not None:
        updates.extend(["expression = ?", "evaluated_at = NULL"])
        params.extend([json.dumps(payload.expression), None])
        set_expression = True
        _invalidate_dependents(db, list_id)
    elif payload.clear_expression:
        updates.extend(["expression = NULL", "evaluated_at = ?"])
        params.append(now_ns())

    if updates:
        params.append(list_id)
        db.execute(f"UPDATE node_lists SET {', '.join(updates)} WHERE id = ?", params)

    if payload.members is not None:
        db.execute("DELETE FROM node_list_members WHERE list_id = ?", (list_id,))
        for nid in payload.members:
            db.execute(
                "INSERT OR IGNORE INTO node_list_members (list_id, node_id) VALUES (?, ?)",
                (list_id, nid),
            )
        members_changed = True
    if payload.add_members:
        for nid in payload.add_members:
            db.execute(
                "INSERT OR IGNORE INTO node_list_members (list_id, node_id) VALUES (?, ?)",
                (list_id, nid),
            )
        members_changed = True
    if payload.remove_members:
        for nid in payload.remove_members:
            db.execute(
                "DELETE FROM node_list_members WHERE list_id = ? AND node_id = ?",
                (list_id, nid),
            )
        members_changed = True

    if members_changed:
        db.execute(
            "UPDATE node_lists SET evaluated_at = ? WHERE id = ?", (now_ns(), list_id)
        )
        _invalidate_dependents(db, list_id)

    db.commit()

    if set_expression:
        _materialize(db, list_id)

    row = db.execute(
        "SELECT id, name, expression, evaluated_at FROM node_lists WHERE id = ?", (list_id,)
    ).fetchone()
    lid, name, expr_json, evaluated_at = row
    expression = json.loads(expr_json) if expr_json else None
    return {
        "id": lid,
        "name": name,
        "expression": expression,
        "stale": expression is not None and evaluated_at is None,
        "members": _get_members(db, list_id),
    }


@router.delete("/{list_id}", status_code=204)
def delete_node_list(list_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT 1 FROM node_lists WHERE id = ?", (list_id,)).fetchone() is None:
        raise HTTPException(404, "List not found")
    _invalidate_dependents(db, list_id)
    db.execute("DELETE FROM node_list_members WHERE list_id = ?", (list_id,))
    db.execute("DELETE FROM node_lists WHERE id = ?", (list_id,))
    db.commit()


@router.post("/{list_id}/evaluate")
def force_evaluate(list_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = db.execute("SELECT expression FROM node_lists WHERE id = ?", (list_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "List not found")
    if row[0] is None:
        raise HTTPException(400, "List has no expression to evaluate")
    members = _materialize(db, list_id)
    return {"list_id": list_id, "member_count": len(members)}
