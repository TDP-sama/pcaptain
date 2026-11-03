from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends
import asyncio
import json
import re

from services.context import get_app_context, AppContext
from services.logger import get_logger
from services.scan import (
    PCAP_FILE_KEY_PREFIX,
    PROTOCOCOL_INDEX_PREFIX,
    SORT_INDEX_FILENAME,
    SORT_INDEX_PATH,
    SORT_INDEX_SIZE,
    SORT_INDEX_PACKET_COUNT,
    get_all_protocols
)
from utils.protocols_utils import rank_protocols


router = APIRouter(tags=["Search"])
logger = get_logger(__name__)

# Facets are counted over at most this many matching files to keep a broad
# query (e.g. "eth") cheap on large catalogs.
FACET_SAMPLE_LIMIT = 5000


class SortField(str, Enum):
    filename = "filename"
    size = "size_bytes"
    count = "protocol_packet_count"
    path = "path"


SORT_FIELD_TO_INDEX = {
    SortField.filename: SORT_INDEX_FILENAME,
    SortField.path: SORT_INDEX_PATH,
    SortField.size: SORT_INDEX_SIZE,
    SortField.count: SORT_INDEX_PACKET_COUNT,
}


@dataclass
class ParsedQuery:
    """What a search string means.

    A file matches when it has every protocol in `all`, at least one protocol
    from each group in `any`, none of the protocols in `none`, and a filename
    containing every string in `name` and none in `not_name`.
    """
    all: list[str] = field(default_factory=list)
    any: list[list[str]] = field(default_factory=list)
    none: list[str] = field(default_factory=list)
    name: list[str] = field(default_factory=list)
    not_name: list[str] = field(default_factory=list)
    # Parts of an OR group that are not known protocols; reported, not searched.
    unknown: list[str] = field(default_factory=list)

    @property
    def wanted_protocols(self) -> set[str]:
        return set(self.all) | {p for group in self.any for p in group}

    def is_empty(self) -> bool:
        return not (self.all or self.any or self.none or self.name or self.not_name)


def _tokenize(raw: str) -> list[str]:
    tokens = [t for t in re.split(r"[\s,]+", raw.strip()) if t]
    # "sip OR rtp" is the same as "sip|rtp"
    merged: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i].upper() == "OR" and merged and i + 1 < len(tokens):
            merged[-1] = f"{merged[-1]}|{tokens[i + 1]}"
            i += 2
            continue
        merged.append(tokens[i])
        i += 1
    return merged


def parse_query(raw: str, known_protocols: set[str]) -> ParsedQuery:
    """Grammar (tokens separated by spaces or commas):

      sip           file contains protocol sip (if sip is a known protocol),
                    otherwise its filename contains "sip"
      !sip  -sip    file does not contain sip
      isup|bicc     file contains isup or bicc (also: "isup OR bicc")
      name:camel    filename contains "camel" (also file:camel)
    """
    q = ParsedQuery()

    def add_unique(target: list, value) -> None:
        if value not in target:
            target.append(value)

    for token in _tokenize(raw.lower()):
        negate = token[0] in "!-" and len(token) > 1
        if negate:
            token = token[1:]

        prefix, _, rest = token.partition(":")
        if rest and prefix in ("name", "file"):
            add_unique(q.not_name if negate else q.name, rest)
            continue

        if "|" in token:
            parts = [p for p in token.split("|") if p]
            group = [p for p in parts if p in known_protocols]
            q.unknown.extend(p for p in parts if p not in known_protocols)
            if not group:
                continue
            if negate:
                # !(a|b) == !a !b
                for p in group:
                    add_unique(q.none, p)
            elif len(group) == 1:
                add_unique(q.all, group[0])
            elif group not in q.any:
                q.any.append(group)
            continue

        if token in known_protocols:
            add_unique(q.none if negate else q.all, token)
        else:
            add_unique(q.not_name if negate else q.name, token)

    return q


def _proto_key(protocol: str) -> str:
    return f"{PROTOCOCOL_INDEX_PREFIX}:{protocol}"


def _matching_ids(redis, q: ParsedQuery) -> set[str]:
    """Evaluate a parsed query with Redis set operations. Runs in a thread."""
    if q.all:
        ids = redis.sinter([_proto_key(p) for p in q.all])
    elif q.any:
        ids = redis.sunion([_proto_key(p) for p in q.any[0]])
    else:
        # Every indexed file has a size score, so this zset is the full catalog.
        ids = set(redis.zrange(SORT_INDEX_SIZE, 0, -1))

    for group in q.any:
        if not ids:
            break
        ids &= redis.sunion([_proto_key(p) for p in group])

    if ids and q.none:
        ids -= redis.sunion([_proto_key(p) for p in q.none])

    if ids and (q.name or q.not_name):
        ordered = list(ids)
        pipe = redis.pipeline()
        for h in ordered:
            pipe.hget(f"{PCAP_FILE_KEY_PREFIX}:{h}", "filename")
        names = pipe.execute()
        ids = {
            h for h, fname in zip(ordered, names)
            if fname is not None
            and all(s in fname.lower() for s in q.name)
            and not any(s in fname.lower() for s in q.not_name)
        }

    return ids


def _sorted_page(redis, ids: set[str], sort_index: str, descending: bool, start: int, count: int) -> list[str]:
    ordered = list(ids)
    pipe = redis.pipeline()
    for h in ordered:
        pipe.zscore(sort_index, h)
    scores = pipe.execute()
    # Files missing from the sort index (e.g. before the name index is rebuilt)
    # go last; the hash keeps the order stable between pages.
    missing = float("-inf") if descending else float("inf")
    ranked = sorted(
        zip(ordered, scores),
        key=lambda pair: (missing if pair[1] is None else pair[1], pair[0]),
        reverse=descending,
    )
    return [h for h, _ in ranked[start:start + count]]


def _facets(redis, ids: set[str]) -> list[dict]:
    sample = list(ids)[:FACET_SAMPLE_LIMIT]
    pipe = redis.pipeline()
    for h in sample:
        pipe.hget(f"{PCAP_FILE_KEY_PREFIX}:{h}", "protocols")
    counts: Counter[str] = Counter()
    for protocols in pipe.execute():
        if protocols:
            counts.update(p for p in protocols.split(",") if p)
    return [{"protocol": p, "files": n} for p, n in counts.most_common()]


@router.get("/search", summary="Search for pcaps by protocol or filename")
async def search_pcaps(
    protocol: str = Query(
        "",
        description=(
            "Query. `sip rtp` = both, `isup|bicc` = either, `!rtp` = without, "
            "`name:camel` = filename contains. Unknown words match filenames."
        ),
    ),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    sort_by: SortField = Query(SortField.filename),
    descending: bool = Query(False),
    facets: bool = Query(True, description="Include protocol counts over the matching files"),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    known = {p.lower() for p in await get_all_protocols(redis)}
    q = parse_query(protocol, known)

    ids = await asyncio.to_thread(_matching_ids, redis, q)
    total = len(ids)
    logger.info("Search %r -> %s, %d results", protocol, asdict(q), total)

    response = {
        "total": total,
        "page": page,
        "limit": limit,
        "data": [],
        "query": asdict(q),
        "facets": [],
        "suggestions": [],
    }

    if total == 0:
        # Offer close protocol names for words that matched nothing.
        words = q.name + q.unknown
        seen: set[str] = set()
        for word in words:
            for p in rank_protocols(word, list(known), max_dist=0.45)[:3]:
                if p not in seen:
                    seen.add(p)
                    response["suggestions"].append(p)
        return response

    sort_index = SORT_FIELD_TO_INDEX[sort_by]
    start = (page - 1) * limit
    page_ids = await asyncio.to_thread(_sorted_page, redis, ids, sort_index, descending, start, limit)

    pipe = redis.pipeline()
    for h in page_ids:
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
    rows = await asyncio.to_thread(pipe.execute)

    wanted = q.wanted_protocols
    internal_pcap_root = context.config.pcap.root_directory
    prefix_str = context.config.pcap.prefix_str
    for h, row in zip(page_ids, rows):
        if not row:
            continue
        counts = json.loads(row.get("protocol_counts", "{}"))
        row["hash"] = h
        row["matched_protocols"] = [p for p in counts if p.lower() in wanted]
        row["searched_protocol"] = protocol
        if prefix_str:
            row["path"] = row["path"].replace(internal_pcap_root, prefix_str, 1)
        response["data"].append(row)

    if facets:
        response["facets"] = await asyncio.to_thread(_facets, redis, ids)

    return response
