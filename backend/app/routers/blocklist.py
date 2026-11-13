import uuid
from fastapi import APIRouter, HTTPException
from typing import List
from app.database import get_db_connection
from app.schemas import BlocklistRuleCreate, BlocklistRuleResponse

router = APIRouter(prefix="/blocklist", tags=["Blocklist Management"])

@router.get("", response_model=List[BlocklistRuleResponse])
def get_blocklist():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, pattern, reason, created_at FROM blocklist ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [
            BlocklistRuleResponse(
                id=r["id"],
                pattern=r["pattern"],
                reason=r["reason"],
                created_at=r["created_at"]
            )
            for r in rows
        ]

@router.post("", response_model=BlocklistRuleResponse, status_code=201)
def add_blocklist_rule(req: BlocklistRuleCreate):
    rule_id = "blk-" + str(uuid.uuid4())[:8]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blocklist (id, pattern, reason)
            VALUES (?, ?, ?)
        """, (rule_id, req.pattern.strip(), req.reason.strip()))
        conn.commit()

        cursor.execute("SELECT id, pattern, reason, created_at FROM blocklist WHERE id = ?", (rule_id,))
        r = cursor.fetchone()
        return BlocklistRuleResponse(
            id=r["id"],
            pattern=r["pattern"],
            reason=r["reason"],
            created_at=r["created_at"]
        )

@router.delete("/{rule_id}", status_code=204)
def delete_blocklist_rule(rule_id: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM blocklist WHERE id = ?", (rule_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found.")
        conn.commit()
    return None
