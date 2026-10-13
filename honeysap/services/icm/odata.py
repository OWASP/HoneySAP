# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

"""OData V2 queries answered from recorded entity sets.

The launchpad bundle holds complete recordings of the entity sets of the
sample apps. Requests the recording does not cover (another page, sort
order, filter or entity) are answered from them: key lookup, navigation,
$filter, $orderby, $skip, $top, $select, $expand, $inlinecount, $count, in the JSON format of SAP Gateway."""

# Standard imports
import json
import re
from collections import OrderedDict
from urllib.parse import unquote
# External imports
# Custom imports


DATE = re.compile(r'"/Date\(([^)"]*)\)/"')


def _dumps(document):
    """JSON as SAP Gateway writes it: compact, non-ASCII characters as they
    are and dates as "\\/Date(...)\\/" """
    text = json.dumps(document, separators=(",", ":"), ensure_ascii=False)
    return DATE.sub(r'"\\/Date(\1)\\/"', text)


class QueryError(ValueError):
    """Query option that cannot be evaluated"""


def _results(data):
    """Entities of a recorded JSON response, or None"""
    try:
        document = json.loads(data, object_pairs_hook=OrderedDict)
    except ValueError:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("d"), dict):
        return None
    results = document["d"].get("results")
    return results if isinstance(results, list) else None


def _entity_key(entity):
    """Key predicate of an entity, from its URI"""
    uri = (entity.get("__metadata") or {}).get("uri", "")
    match = re.search(r"\(([^()]*)\)$", uri)
    return _normalize_key(match.group(1)) if match else None


def _normalize_key(key):
    key = unquote(key)
    return re.sub(r"(guid'[0-9a-fA-F-]+')", lambda m: m.group(1).lower(), key.replace(" ", ""))


class EntityStore(object):
    """Complete entity sets recorded per service"""

    def __init__(self):
        self.sets = {}
        # Navigation property names per entity type
        self.navigations = {}

    def add(self, service, entity_set, data, expand=""):
        """Keep the largest recording of an entity set. expand is the $expand
        of the recording; it names navigations that are null everywhere."""
        results = _results(data)
        if not results:
            return
        key = (service, entity_set)
        if key not in self.sets or len(results) > len(self.sets[key]):
            self.sets[key] = results
        for entity in results:
            self._learn(entity)
            names = self.navigations.setdefault((entity.get("__metadata") or {}).get("type"), set())
            names.update(path.split("/")[0] for path in expand.split(",") if path)

    def _learn(self, entity):
        names = self.navigations.setdefault((entity.get("__metadata") or {}).get("type"), set())
        for name, value in entity.items():
            if isinstance(value, dict) and ("__deferred" in value or _is_navigation(value)):
                names.add(name)
                for item in value.get("results") or ([value] if "__metadata" in value else []):
                    self._learn(item)

    def query(self, service, resource, options):
        """JSON document (as text) for a request on a recorded entity set,
        or None. resource is the path below the service root; options the
        decoded query options."""
        if resource.endswith("/$count"):
            resource, count = resource[:-len("/$count")], True
        else:
            count = False
        segments = [segment for segment in resource.split("/") if segment]
        if not segments:
            return None
        match = re.match(r"^([A-Za-z_][\w.]*)(?:\((.*)\))?$", segments[0])
        if not match or (service, match.group(1)) not in self.sets:
            return None
        entities = self.sets[(service, match.group(1))]
        single = None
        if match.group(2) is not None:
            single = self.lookup(entities, match.group(2))
            if single is None:
                return None
        for navigation in segments[1:]:
            if single is None:
                return None
            value = single.get(navigation)
            if not isinstance(value, dict) or "__deferred" in value:
                return None
            if isinstance(value.get("results"), list):
                entities, single = value["results"], None
            else:
                single = value
        try:
            if single is not None:
                if count:
                    return "1"
                return _dumps({"d": self.shape(single, options)})
            selected = self.select_entities(entities, options)
            skip = self.number(options.get("$skip"), 0)
            top = self.number(options.get("$top"), None)
        except QueryError:
            return None
        if count:
            return str(len(selected))
        total = len(selected)
        selected = selected[skip:] if top is None else selected[skip:skip + top]
        document = OrderedDict()
        if options.get("$inlinecount") == "allpages":
            document["__count"] = str(total)
        document["results"] = [self.shape(entity, options) for entity in selected]
        return _dumps({"d": document})

    @staticmethod
    def number(value, default):
        if value is None:
            return default
        if not value.isdigit():
            raise QueryError("invalid number %s" % value)
        return int(value)

    @staticmethod
    def lookup(entities, key):
        wanted = _normalize_key(key)
        for entity in entities:
            stored = _entity_key(entity)
            if stored == wanted:
                return entity
            # Single key properties may be addressed with or without their name
            if stored and "," not in stored and "," not in wanted and \
               stored.split("=", 1)[-1] == wanted.split("=", 1)[-1]:
                return entity
        return None

    def select_entities(self, entities, options):
        selected = list(entities)
        if options.get("$filter"):
            condition = FilterParser(options["$filter"]).parse()
            selected = [entity for entity in selected if condition(entity)]
        if options.get("$orderby"):
            # Ties keep the key order, like the database
            selected.sort(key=lambda entity: _entity_key(entity) or "")
            for part in reversed(options["$orderby"].split(",")):
                path, _, direction = part.strip().partition(" ")
                descending = direction.strip().lower() == "desc"
                selected.sort(key=lambda entity, path=path: _sort_key(_value(entity, path)),
                              reverse=descending)
        return selected

    def shape(self, entity, options):
        """Apply $select and $expand to an entity"""
        selects = [path.strip() for path in (options.get("$select") or "").split(",") if path.strip()]
        expands = [path.strip() for path in (options.get("$expand") or "").split(",") if path.strip()]
        return self._shape(entity, selects, expands)

    def _shape(self, entity, selects, expands):
        navigations = self.navigations.get((entity.get("__metadata") or {}).get("type"), set())
        expanded = {path.split("/")[0] for path in expands}
        selected = {path.split("/")[0] for path in selects}
        shaped = OrderedDict()
        for name, value in entity.items():
            if name == "__metadata":
                shaped[name] = value
                continue
            if selects and "*" not in selected and name not in selected:
                continue
            if name not in navigations:
                shaped[name] = value
                continue
            if name not in expanded or (isinstance(value, dict) and "__deferred" in value):
                uri = (entity.get("__metadata") or {}).get("uri", "")
                shaped[name] = {"__deferred": {"uri": "%s/%s" % (uri, name)}}
                continue
            # Selecting the navigation itself selects all its properties
            inner_selects = [] if name in selects else \
                [path.split("/", 1)[1] for path in selects if path.startswith(name + "/")]
            inner_expands = [path.split("/", 1)[1] for path in expands
                             if path.startswith(name + "/")]
            if value is None:
                shaped[name] = None
            elif isinstance(value.get("results"), list):
                # Expanded collections come in key order
                items = sorted(value["results"], key=lambda item: _entity_key(item) or "")
                shaped[name] = {"results": [self._shape(item, inner_selects, inner_expands)
                                            for item in items]}
            else:
                shaped[name] = self._shape(value, inner_selects, inner_expands)
        return shaped


def _is_navigation(value):
    """Expanded navigation (entity or collection), not a complex value"""
    return isinstance(value.get("results"), list) or "uri" in (value.get("__metadata") or {})


def _value(entity, path):
    value = entity
    for name in path.split("/"):
        if not isinstance(value, dict):
            return None
        value = value.get(name)
        if isinstance(value, dict) and "__deferred" in value:
            return None
    return value


def _sort_key(value):
    if value is None:
        return (0, "")
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, (int, float)):
        return (1, value)
    try:
        return (1, float(value))
    except (TypeError, ValueError):
        # Strings sort case-insensitively, like the database collation
        return (2, str(value).lower())


def _compare(left, right):
    """Values of a comparison: numbers compare as numbers, Decimal values are
    strings in OData JSON"""
    if isinstance(left, (int, float)) and not isinstance(left, bool) or \
       isinstance(right, (int, float)) and not isinstance(right, bool):
        try:
            return float(left), float(right)
        except (TypeError, ValueError):
            pass
    return left, right


TOKEN = re.compile(r"\s*(?:(?P<string>'(?:[^']|'')*')|(?P<typed>(?:guid|datetime|datetimeoffset|"
                   r"time|X|binary)'[^']*')|(?P<number>-?\d+(?:\.\d+)?[mMdDfFlL]?)|"
                   r"(?P<name>[A-Za-z_][\w./]*)|(?P<symbol>[(),]))")
OPERATORS = {"eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
             "gt": lambda a, b: a is not None and b is not None and a > b,
             "ge": lambda a, b: a is not None and b is not None and a >= b,
             "lt": lambda a, b: a is not None and b is not None and a < b,
             "le": lambda a, b: a is not None and b is not None and a <= b}
FUNCTIONS = {
    "substringof": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.lower() in b.lower(),
    "startswith": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.startswith(b),
    "endswith": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.endswith(b),
    "tolower": lambda a: a.lower() if isinstance(a, str) else a,
    "toupper": lambda a: a.upper() if isinstance(a, str) else a,
    "trim": lambda a: a.strip() if isinstance(a, str) else a,
}


class FilterParser(object):
    """$filter expressions: comparisons, and/or/not, parentheses and the
    string functions used by Fiori elements"""

    def __init__(self, text):
        self.tokens = []
        position = 0
        while position < len(text):
            match = TOKEN.match(text, position)
            if not match or match.end() == position:
                if text[position:].strip():
                    raise QueryError("cannot parse filter at %s" % text[position:])
                break
            kind = match.lastgroup
            self.tokens.append((kind, match.group(kind)))
            position = match.end()
        self.position = 0

    def peek(self):
        return self.tokens[self.position] if self.position < len(self.tokens) else (None, None)

    def take(self, value=None):
        token = self.peek()
        if token[0] is None or (value is not None and token[1].lower() != value):
            raise QueryError("unexpected token %s" % (token[1],))
        self.position += 1
        return token

    def parse(self):
        expression = self.disjunction()
        if self.position != len(self.tokens):
            raise QueryError("trailing tokens")
        return expression

    def disjunction(self):
        left = self.conjunction()
        while self.peek()[0] == "name" and self.peek()[1].lower() == "or":
            self.take()
            right = self.conjunction()
            left = (lambda first, second: lambda e: bool(first(e)) or bool(second(e)))(left, right)
        return left

    def conjunction(self):
        left = self.negation()
        while self.peek()[0] == "name" and self.peek()[1].lower() == "and":
            self.take()
            right = self.negation()
            left = (lambda first, second: lambda e: bool(first(e)) and bool(second(e)))(left, right)
        return left

    def negation(self):
        if self.peek()[0] == "name" and self.peek()[1].lower() == "not":
            self.take()
            operand = self.negation()
            return lambda e: not operand(e)
        return self.comparison()

    def comparison(self):
        left = self.operand()
        kind, value = self.peek()
        if kind == "name" and value.lower() in OPERATORS:
            self.take()
            right = self.operand()
            operator = OPERATORS[value.lower()]
            return lambda e: operator(*_compare(left(e), right(e)))
        return left

    def operand(self):
        kind, value = self.take()
        if kind == "symbol" and value == "(":
            expression = self.disjunction()
            self.take(")")
            return expression
        if kind == "string":
            text = value[1:-1].replace("''", "'")
            return lambda e: text
        if kind == "typed":
            literal = value[value.index("'") + 1:-1]
            if value.lower().startswith("guid"):
                literal = literal.lower()
            return lambda e: literal
        if kind == "number":
            number = float(value.rstrip("mMdDfFlL"))
            return lambda e: number
        if kind == "name":
            lower = value.lower()
            if lower in ("true", "false"):
                return lambda e: lower == "true"
            if lower == "null":
                return lambda e: None
            if lower in FUNCTIONS and self.peek() == ("symbol", "("):
                self.take("(")
                arguments = [self.disjunction()]
                while self.peek() == ("symbol", ","):
                    self.take(",")
                    arguments.append(self.disjunction())
                self.take(")")
                function = FUNCTIONS[lower]
                return lambda e: function(*[argument(e) for argument in arguments])
            return lambda e: _guid(_value(e, value))
        raise QueryError("unexpected token %s" % value)


def _guid(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}", value):
        return value.lower()
    return value
