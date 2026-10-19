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
$filter, $orderby, $skip, $top, $select, $expand, $inlinecount, $count, in
the JSON format of SAP Gateway.

Invalid requests raise ODataError with the messages of SAP Gateway and of
the SADL runtime behind the sample services. Property types come from the
recorded $metadata of the service, or from the recorded entities."""

# Standard imports
import json
import math
import re
from collections import OrderedDict
from urllib.parse import unquote
from xml.etree import ElementTree
# External imports
# Custom imports


DATE = re.compile(r'"/Date\(([^)"]*)\)/"')
MAX_INT32 = 2147483647
# Deeper filter expressions are refused; parentheses do not count
MAX_DEPTH = 100


class ODataError(Exception):
    """Error answered like SAP Gateway. details is None for errors of the
    Gateway hub, else the (code, message) error details of the service."""

    def __init__(self, status, code, message, details=None):
        super(ODataError, self).__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def invalid_option():
    return ODataError(400, "005056A509B11EE1B9A8FEC11C22F78E", "Invalid system query options value")


def uri_violation():
    return ODataError(400, "005056A509B11EE1B9A8FEC11C21F78E", "The URI is violating the "
                      "construction rules defined in the Data Services specification")


def malformed_request():
    return ODataError(400, "005056A509B11ED1B9BF94F386DD82E6", "The Data Services Request "
                      "could not be understood due to malformed syntax")


def internal_error():
    return ODataError(500, "0050569259751EE4BA9710043F8A5115", "In the context of Data "
                      "Services an unknown internal server error occurred")


def segment_not_found(segment):
    return ODataError(404, "005056A509B11EE1B9A8FEC11C21D78E",
                      "Resource not found for the segment '%s'." % segment)


def entity_not_found(type_name):
    message = "Resource not found for segment '%s'" % type_name
    return ODataError(404, "/IWBEP/CM_MGW_RT/020", message,
                      [("/IWBEP/CX_MGW_BUSI_EXCEPTION", message)])


def property_not_found(name, type_name):
    return ODataError(400, "005056A509B11EE1B9A8FEA8DE87F78E",
                      "Property %s not found in type %s" % (name, type_name))


def invalid_token(position):
    return ODataError(400, "005056A509B11EE1B9A8FEC11C21178E",
                      "Invalid token detected at position %d" % position)


def parameter_type(function, position):
    return ODataError(400, "005056A509B11EE1BB8AF4A65EC3CA20",
                      "Invalid parametertype used at function '%s' (Position: %d)" %
                      (function, position))


def _dumps(document):
    """JSON as SAP Gateway writes it: compact, non-ASCII characters as they
    are and dates as "\\/Date(...)\\/" """
    text = json.dumps(document, separators=(",", ":"), ensure_ascii=False)
    return DATE.sub(r'"\\/Date(\1)\\/"', text)


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


def _short(name):
    """Entity type name without its namespace"""
    return name.rsplit(".", 1)[-1] if name else None


def _entity_type(entity):
    return _short((entity.get("__metadata") or {}).get("type"))


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_metadata(data):
    """Entity types ({name: (properties, navigations)}) and entity sets
    ({name: type}) of a $metadata document, or None. Properties map to their
    Edm type, navigations to their target type."""
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return None
    associations = {}
    for element in root.iter():
        if _local(element.tag) == "Association":
            associations[element.get("Name")] = {end.get("Role"): _short(end.get("Type"))
                                                 for end in element if _local(end.tag) == "End"}
    types, sets = {}, {}
    for element in root.iter():
        tag = _local(element.tag)
        if tag == "EntityType":
            properties, navigations = OrderedDict(), {}
            for child in element:
                if _local(child.tag) == "Property":
                    properties[child.get("Name")] = child.get("Type")
                elif _local(child.tag) == "NavigationProperty":
                    ends = associations.get(_short(child.get("Relationship")), {})
                    navigations[child.get("Name")] = ends.get(child.get("ToRole"))
            types[element.get("Name")] = (properties, navigations)
        elif tag == "EntitySet":
            sets[element.get("Name")] = _short(element.get("EntityType"))
    return types, sets


class EntityStore(object):
    """Complete entity sets recorded per service"""

    def __init__(self):
        self.sets = {}
        # Entity types per service, from $metadata and from the recordings
        self.metadata = {}
        self.observed = {}

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
            self._learn(service, entity)
            _, navigations = self.observed[(service, _entity_type(entity))]
            for path in expand.split(","):
                if path:
                    navigations.setdefault(path.split("/")[0], None)

    def add_metadata(self, service, data):
        model = parse_metadata(data)
        if model is not None:
            self.metadata[service] = model

    def _learn(self, service, entity):
        properties, navigations = self.observed.setdefault(
            (service, _entity_type(entity)), (OrderedDict(), {}))
        for name, value in entity.items():
            if name == "__metadata":
                continue
            if isinstance(value, dict) and ("__deferred" in value or _is_navigation(value)):
                items = value.get("results") or ([value] if "__metadata" in value else [])
                if items or name not in navigations:
                    navigations[name] = _entity_type(items[0]) if items else None
                for item in items:
                    self._learn(service, item)
            elif name not in navigations:
                properties.setdefault(name, None)

    def describe(self, service, type_name):
        """(properties, navigations) of an entity type, or None. Properties
        map to their Edm type, navigations to their target type; both are
        None when unknown."""
        types, _ = self.metadata.get(service, ({}, {}))
        if type_name in types:
            return types[type_name]
        return self.observed.get((service, type_name))

    def set_type(self, service, entity_set, entities):
        _, sets = self.metadata.get(service, ({}, {}))
        if entity_set in sets:
            return sets[entity_set]
        return _entity_type(entities[0]) if entities else None

    def resolve(self, service, type_name, path, missing):
        """Edm type of a property path, "navigation" for a navigation and
        None when unknown. missing(name, type) is raised for unknown names."""
        segments = path.split("/")
        for position, segment in enumerate(segments):
            last = position == len(segments) - 1
            description = self.describe(service, type_name)
            if description is None:
                return None
            properties, navigations = description
            if last and segment in properties:
                return properties[segment]
            if segment in navigations:
                if last:
                    return "navigation"
                type_name = navigations[segment]
                continue
            raise missing(segment, type_name)
        return None

    def query(self, service, resource, options):
        """JSON document (as text) for a request on a recorded entity set,
        or None. resource is the path below the service root; options the
        decoded query options. Raises ODataError for invalid requests."""
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
        type_name = self.set_type(service, match.group(1), entities)
        self.check_segments(service, type_name, segments[1:])
        single = None
        if match.group(2) is not None:
            single = self.lookup(entities, match.group(2))
            if single is None:
                raise entity_not_found(type_name)
        for navigation in segments[1:]:
            if single is None:
                return None
            description = self.describe(service, type_name)
            if description is not None and navigation in description[0]:
                # Property values are not served by the SADL runtime
                raise entity_not_found(type_name)
            value = single.get(navigation)
            if not isinstance(value, dict) or "__deferred" in value:
                return None
            if isinstance(value.get("results"), list):
                entities, single = value["results"], None
                type_name = (description[1].get(navigation) if description else None) or \
                    (_entity_type(entities[0]) if entities else None)
            else:
                single = value
                type_name = _entity_type(value)
        top = self.number(options.get("$top"))
        skip = self.number(options.get("$skip")) or 0
        if options.get("$inlinecount") not in (None, "", "allpages", "none"):
            raise invalid_option()
        selects = self.paths(options.get("$select"))
        expands = self.paths(options.get("$expand"))
        self.check_paths(service, type_name, selects, expands)
        if single is not None:
            if count:
                return "1"
            return _dumps({"d": self.shape(service, single, selects, expands)})
        selected = self.select_entities(service, type_name, entities, options)
        if count:
            return str(len(selected))
        total = len(selected)
        selected = selected[skip:] if top is None else selected[skip:skip + top]
        document = OrderedDict()
        if options.get("$inlinecount") == "allpages":
            document["__count"] = str(total)
        document["results"] = [self.shape(service, entity, selects, expands)
                               for entity in selected]
        return _dumps({"d": document})

    def check_segments(self, service, type_name, navigations):
        """Navigations of the resource path are checked before entities are
        read; the last segment may be a property"""
        for position, navigation in enumerate(navigations):
            description = self.describe(service, type_name)
            if description is None:
                return
            if navigation in description[0] and position == len(navigations) - 1:
                return
            if navigation not in description[1]:
                raise segment_not_found(navigation)
            type_name = description[1][navigation]

    @staticmethod
    def number(value):
        if not value:
            return None
        if not value.isdigit() or int(value) > MAX_INT32:
            raise invalid_option()
        return int(value)

    @staticmethod
    def paths(value):
        if not value:
            return []
        paths = [path.strip() for path in value.split(",")]
        if not all(paths):
            raise uri_violation()
        return paths

    def check_paths(self, service, type_name, selects, expands):
        """Unknown names in $select and $expand are unknown segments"""
        def missing(name, _):
            return segment_not_found(name)
        for path in selects:
            if path != "*" and not path.endswith("/*"):
                self.resolve(service, type_name, path, missing)
        for path in expands:
            if self.resolve(service, type_name, path, missing) not in ("navigation", None):
                raise segment_not_found(path.split("/")[-1])

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

    def select_entities(self, service, type_name, entities, options):
        selected = list(entities)
        if options.get("$filter"):
            condition = FilterParser(options["$filter"], self, service, type_name).parse()
            selected = [entity for entity in selected if condition(entity)]
        if options.get("$orderby"):
            order = self.order(service, type_name, options["$orderby"])
            # Ties keep the key order, like the database
            selected.sort(key=lambda entity: _entity_key(entity) or "")
            for path, descending in reversed(order):
                selected.sort(key=lambda entity, path=path: _sort_key(_value(entity, path)),
                              reverse=descending)
        return selected

    def order(self, service, type_name, value):
        order = []
        for part in self.paths(value):
            words = part.split()
            direction = words[1].lower() if len(words) > 1 else "asc"
            if len(words) > 2 or direction not in ("asc", "desc"):
                raise ODataError(400, "005056A509B11EE1B9A8FEC11C20F78E",
                                 "Invalid sortorder '%s' detected" % " ".join(words[1:]))
            if self.resolve(service, type_name, words[0], property_not_found) == "navigation":
                raise internal_error()
            order.append((words[0], direction == "desc"))
        return order

    def shape(self, service, entity, selects, expands):
        """Apply $select and $expand to an entity"""
        description = self.describe(service, _entity_type(entity))
        navigations = description[1] if description else {}
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
                shaped[name] = {"results": [self.shape(service, item, inner_selects, inner_expands)
                                            for item in items]}
            else:
                shaped[name] = self.shape(service, value, inner_selects, inner_expands)
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


def _compare(operator, left, right):
    """Numbers compare as numbers (Decimal values are strings in OData
    JSON); values that cannot be compared do not match"""
    if isinstance(left, (int, float)) and not isinstance(left, bool) or \
       isinstance(right, (int, float)) and not isinstance(right, bool):
        try:
            left, right = float(left), float(right)
        except (TypeError, ValueError):
            pass
    try:
        return bool(operator(left, right))
    except TypeError:
        return False


# $filter expressions

TOKEN = re.compile(r"(?P<string>'(?:[^']|'')*')|(?P<typed>(?:guid|datetime|datetimeoffset|"
                   r"time|X|binary)'[^']*')|(?P<number>-?\d+(?:\.\d+)?[mMdDfFlL]?)|"
                   r"(?P<name>[A-Za-z_][\w./]*)|(?P<symbol>[(),])")
# Binary operators and their precedence; not binds closer than comparisons
BINARY = {"or": 1, "and": 2, "eq": 3, "ne": 3, "gt": 3, "ge": 3, "lt": 3, "le": 3}
NOT = 4
OPERATORS = {"eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
             "gt": lambda a, b: a is not None and b is not None and a > b,
             "ge": lambda a, b: a is not None and b is not None and a >= b,
             "lt": lambda a, b: a is not None and b is not None and a < b,
             "le": lambda a, b: a is not None and b is not None and a <= b}
STRING, BOOLEAN, INT32 = "Edm.String", "Edm.Boolean", "Edm.Int32"
# Functions of OData V2: minimum and maximum parameters, parameter types and
# result type. The SADL runtime supports only those evaluated.
FUNCTIONS = {
    "substringof": (2, 2, (STRING, STRING), BOOLEAN),
    "startswith": (2, 2, (STRING, STRING), BOOLEAN),
    "endswith": (2, 2, (STRING, STRING), BOOLEAN),
    "tolower": (1, 1, (STRING,), STRING),
    "toupper": (1, 1, (STRING,), STRING),
    "trim": (1, 1, (STRING,), STRING),
    "length": (1, 1, (STRING,), INT32),
    "indexof": (2, 2, (STRING, STRING), INT32),
    "replace": (3, 3, (STRING, STRING, STRING), STRING),
    "substring": (2, 3, (STRING, INT32, INT32), STRING),
    "concat": (2, 2, (STRING, STRING), STRING),
    "year": (1, 1, (None,), INT32), "month": (1, 1, (None,), INT32),
    "day": (1, 1, (None,), INT32), "hour": (1, 1, (None,), INT32),
    "minute": (1, 1, (None,), INT32), "second": (1, 1, (None,), INT32),
    "round": (1, 1, (None,), INT32), "floor": (1, 1, (None,), INT32),
    "ceiling": (1, 1, (None,), INT32),
}
EVALUATED = {
    "substringof": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.lower() in b.lower(),
    "startswith": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.startswith(b),
    "endswith": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.endswith(b),
}
INTEGERS = {"Edm.Byte", "Edm.SByte", "Edm.Int16", "Edm.Int32", "Edm.Int64"}
NUMBERS = INTEGERS | {"Edm.Decimal", "Edm.Double", "Edm.Single"}
TYPED = {"guid": "Edm.Guid", "datetime": "Edm.DateTime", "datetimeoffset": "Edm.DateTimeOffset",
         "time": "Edm.Time", "x": "Edm.Binary", "binary": "Edm.Binary"}


def _category(edm):
    return "number" if edm in NUMBERS else edm


class Node(object):
    """Node of a filter expression: literal, property, not, operator or
    function"""

    __slots__ = ("kind", "name", "position", "children", "value", "depth")

    def __init__(self, kind, name, position, children=(), value=None):
        self.kind = kind
        self.name = name
        self.position = position
        self.children = list(children)
        self.value = value
        self.depth = 1 + max([child.depth for child in self.children] or [0])
        if self.depth > MAX_DEPTH:
            raise internal_error()


class FilterParser(object):
    """$filter expressions: parsed without recursion (operator precedence
    with explicit stacks), checked like SAP Gateway and the SADL runtime, and
    compiled into a predicate on entities"""

    def __init__(self, text, store=None, service=None, type_name=None):
        self.text = text
        self.store = store
        self.service = service
        self.type_name = type_name

    def parse(self):
        node = self.syntax()
        if self.check(node) not in (None, BOOLEAN):
            raise ODataError(400, "005056A509B11EE1B9A8FEC11C22D78E",
                             "Invalid type for '$filter' system query option. "
                             "Expected type is 'Edm.Boolean'")
        self.backend(node)
        return self.compile(node)

    def tokens(self):
        """(kind, value, start, end), positions counted from 1"""
        tokens = []
        position = 0
        while True:
            while position < len(self.text) and self.text[position] == " ":
                position += 1
            if position >= len(self.text):
                return tokens
            match = TOKEN.match(self.text, position)
            if not match:
                # The scanner reports the offset of the character
                raise invalid_token(position)
            kind = match.lastgroup
            tokens.append((kind, match.group(kind), match.start() + 1, match.end()))
            position = match.end()

    def syntax(self):
        """Expression tree. The operator stack holds (kind, name, position,
        precedence or operand count) for "(", "not", "operator" and "call"."""
        tokens = self.tokens()
        operands, operators = [], []
        expect_operand = True
        end = 0
        index = 0
        while index < len(tokens):
            kind, value, start, end = tokens[index]
            following = tokens[index + 1][:2] if index + 1 < len(tokens) else None
            if expect_operand:
                if (kind, value) == ("symbol", "("):
                    if following == ("symbol", ")"):
                        raise ODataError(400, "00505692409C1EE594E4B1F305230158",
                                         "Empty filter expression (Position: %d)" % start)
                    operators.append(("(", "", start, 0))
                elif (kind, value) == ("name", "not"):
                    operators.append(("not", "not", start, NOT))
                elif kind == "name" and following == ("symbol", "("):
                    index += 1
                    end = tokens[index][3]
                    operators.append(("call", value, start, len(operands)))
                    if index + 1 < len(tokens) and tokens[index + 1][:2] == ("symbol", ")"):
                        index += 1
                        end = tokens[index][3]
                        self.close_call(operands, operators.pop())
                        expect_operand = False
                elif kind in ("string", "typed", "number", "name"):
                    operands.append(self.leaf(kind, value, start))
                    expect_operand = False
                else:
                    raise invalid_token(start)
            elif kind == "name" and value.lower() in BINARY:
                precedence = BINARY[value.lower()]
                self.reduce(operands, operators, precedence)
                # Operators are lower case; others parse as an unnamed function
                operators.append(("operator", value if value in BINARY else "", start,
                                  precedence))
                expect_operand = True
            elif (kind, value) == ("symbol", ")"):
                self.reduce(operands, operators, 0)
                if not operators:
                    raise invalid_token(start)
                opening = operators.pop()
                if opening[0] == "call":
                    self.close_call(operands, opening)
            elif (kind, value) == ("symbol", ",") and \
                    self.reduce(operands, operators, 0) and operators[-1][0] == "call":
                expect_operand = True
            else:
                raise invalid_token(start)
            index += 1
        if expect_operand:
            raise ODataError(400, "005056A509B11ED2A7A45ADD820994DA",
                             "Expression expected after position %d" % end)
        self.reduce(operands, operators, 0)
        if operators:
            raise ODataError(400, "005056A509B11EE280B0EE7B018E5A52", "Expected token ) not found")
        return operands[0]

    @staticmethod
    def leaf(kind, value, start):
        if kind == "string":
            return Node("literal", STRING, start, value=value[1:-1].replace("''", "'"))
        if kind == "typed":
            prefix, literal = value[:value.index("'")].lower(), value[value.index("'") + 1:-1]
            return Node("literal", TYPED[prefix], start,
                        value=literal.lower() if prefix == "guid" else literal)
        if kind == "number":
            return Node("literal", "number", start, value=float(value.rstrip("mMdDfFlL")))
        if value in ("true", "false"):
            return Node("literal", BOOLEAN, start, value=value == "true")
        if value == "null":
            return Node("literal", None, start)
        return Node("property", value, start)

    @staticmethod
    def reduce(operands, operators, precedence):
        """Apply the stacked operators binding at least as close. True when
        operators remain."""
        while operators and operators[-1][0] in ("not", "operator") and \
                operators[-1][3] >= precedence:
            kind, name, start, _ = operators.pop()
            if kind == "not":
                operands.append(Node("not", name, start, [operands.pop()]))
            else:
                right, left = operands.pop(), operands.pop()
                operands.append(Node("operator", name, start, [left, right]))
        return bool(operators)

    @staticmethod
    def close_call(operands, call):
        _, name, start, height = call
        arguments = operands[height:]
        del operands[height:]
        operands.append(Node("function", name, start, arguments))

    # Checks of SAP Gateway

    def property_type(self, path):
        if self.store is None:
            return None
        edm = self.store.resolve(self.service, self.type_name, path, property_not_found)
        return None if edm == "navigation" else edm

    def check(self, node):
        """Type of a node, None when unknown"""
        if node.kind == "literal":
            return node.name
        if node.kind == "property":
            return self.property_type(node.name)
        types = [self.check(child) for child in node.children]
        if node.kind == "not":
            if types[0] not in (None, BOOLEAN):
                raise parameter_type("not", node.position)
            return BOOLEAN
        if node.kind == "operator":
            if node.name in ("and", "or"):
                if any(kind not in (None, BOOLEAN) for kind in types):
                    raise parameter_type(node.name, node.position)
            else:
                mismatch = None not in types and _category(types[0]) != _category(types[1])
                if mismatch or not node.name:
                    raise parameter_type(node.name, node.position)
                self.convert(node, types)
            return BOOLEAN
        if node.name not in FUNCTIONS:
            raise property_not_found(node.name, self.type_name)
        minimum, maximum, parameters, result = FUNCTIONS[node.name]
        if len(types) < minimum:
            raise ODataError(400, "005056A509B11EE1B9A8FEC11C20B78E",
                             "Too few parameters for function '%s'" % node.name)
        if len(types) > maximum:
            raise ODataError(400, "005056A509B11EE1B9A8FEC11C20D78E",
                             "Too many parameters for function '%s'" % node.name)
        for kind, parameter in zip(types, parameters):
            if None not in (kind, parameter) and _category(kind) != _category(parameter):
                raise parameter_type(node.name, node.position)
        return result

    @staticmethod
    def convert(node, types):
        """Numbers compared with integer properties are rounded to integers,
        like ABAP converts them (half away from zero)"""
        for child, other in zip(node.children, reversed(types)):
            if child.kind == "literal" and child.name == "number" and other in INTEGERS:
                child.value = float(math.copysign(math.floor(abs(child.value) + 0.5), child.value))

    # Checks of the SADL runtime

    def backend(self, root):
        if root.kind == "property":
            raise unsupported_condition()
        nodes = [root]
        while nodes:
            node = nodes.pop()
            if node.kind == "function" and node.name not in EVALUATED:
                message = "Function %s is not supported" % node.name
                raise ODataError(400, "/IWBEP/CM_MGW_EXPR/000", message,
                                 [("/IWBEP/CX_MGW_EXPR_VISTR_EXCP", message)])
            if node.kind == "operator" and node.name in OPERATORS:
                kinds = [child.kind for child in node.children]
                if kinds == ["property", "property"]:
                    message = "Attribute to attribute comparison is not supported by " \
                              "condensed condition"
                    raise ODataError(501, "CX_SADL_FILT_ATTR_TO_ATTR_COMP", message, [
                        ("CX_SADL_FILT_ATTR_TO_ATTR_COMP", message),
                        ("/IWBEP/CX_MGW_TECH_EXCEPTION", "An exception was raised")])
                if "operator" in kinds or "not" in kinds:
                    raise unsupported_condition()
            nodes.extend(node.children)

    # Evaluation

    def compile(self, node):
        if node.kind == "literal":
            value = node.value
            return lambda e: value
        if node.kind == "property":
            path = node.name
            return lambda e: _guid(_value(e, path))
        children = [self.compile(child) for child in node.children]
        if node.kind == "not":
            operand = children[0]
            return lambda e: not operand(e)
        if node.kind == "function":
            function = EVALUATED[node.name]
            return lambda e: function(*[child(e) for child in children])
        left, right = children
        if node.name == "and":
            return lambda e: bool(left(e)) and bool(right(e))
        if node.name == "or":
            return lambda e: bool(left(e)) or bool(right(e))
        operator = OPERATORS[node.name]
        return lambda e: _compare(operator, left(e), right(e))


def unsupported_condition():
    return ODataError(400, "/IWFND/CM_MGW/546", "Filter condition is not supported - valid", [])


def _guid(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}", value):
        return value.lower()
    return value
