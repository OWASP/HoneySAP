# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

# Standard imports
import json
import random
import unittest
# Custom imports
from honeysap.services.icm.odata import EntityStore, FilterParser, ODataError


ROOT = "https://{{AUTHORITY}}/sap/opu/odata/sap/SHOP/"
SERVICE = "/sap/opu/odata/sap/SHOP/"
METADATA = b"""<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx">
<edmx:DataServices><Schema Namespace="SHOP" xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
<EntityType Name="Product"><Property Name="Id" Type="Edm.String"/>
<Property Name="Name" Type="Edm.String"/><Property Name="Price" Type="Edm.Decimal"/>
<Property Name="Category" Type="Edm.String"/><Property Name="Changed" Type="Edm.DateTime"/>
<Property Name="Stock" Type="Edm.Int32"/><Property Name="Favorite" Type="Edm.Boolean"/>
<NavigationProperty Name="Reviews" Relationship="SHOP.ProductReviews" ToRole="R"/>
<NavigationProperty Name="Supplier" Relationship="SHOP.ProductSupplier" ToRole="S"/></EntityType>
<EntityType Name="Review"><Property Name="Rating" Type="Edm.Int32"/></EntityType>
<EntityType Name="Supplier"><Property Name="Name" Type="Edm.String"/></EntityType>
<Association Name="ProductReviews"><End Type="SHOP.Product" Role="P"/><End Type="SHOP.Review" Role="R"/></Association>
<Association Name="ProductSupplier"><End Type="SHOP.Product" Role="P"/><End Type="SHOP.Supplier" Role="S"/></Association>
<EntityContainer Name="SHOP_Entities"><EntitySet Name="Products" EntityType="SHOP.Product"/></EntityContainer>
</Schema></edmx:DataServices></edmx:Edmx>"""


def product(key, name, price, category, reviews, supplier=None):
    uri = ROOT + "Products('%s')" % key
    return {"__metadata": {"id": uri, "uri": uri, "type": "SHOP.Product"},
            "Id": key, "Name": name, "Price": price, "Category": category,
            "Changed": "/Date(1590728742000)/", "Stock": 5, "Favorite": False,
            "Reviews": {"results": [
                {"__metadata": {"uri": ROOT + "Reviews(guid'%s')" % guid, "type": "SHOP.Review"},
                 "Rating": rating} for guid, rating in reviews]},
            "Supplier": supplier}


PRODUCTS = [
    product("P-3", "beta Chair", "250.00", "Furniture",
            [("0a71e5d7-0000-0000-0000-00000000000b", 4), ("0a71e5d7-0000-0000-0000-00000000000a", 2)]),
    product("P-1", "Alpha Desk", "1200.00", "Furniture", []),
    product("P-2", "Beta Chair", "99.50", "Furniture", []),
    product("P-4", "Gamma Lamp °", "12.00", "Lighting", [],
            supplier={"__metadata": {"uri": ROOT + "Suppliers('S1')", "type": "SHOP.Supplier"},
                      "Name": "Lights Inc"}),
]


class EntityStoreTest(unittest.TestCase):

    def setUp(self):
        self.store = EntityStore()
        self.store.add(SERVICE, "Products",
                       json.dumps({"d": {"__count": "4", "results": PRODUCTS}}).encode(),
                       "Reviews,Supplier")
        self.store.add_metadata(SERVICE, METADATA)

    def error(self, resource, **options):
        with self.assertRaises(ODataError) as raised:
            self.store.query(SERVICE, resource, options)
        return raised.exception.status, raised.exception.message

    def query(self, resource, **options):
        text = self.store.query(SERVICE, resource, options)
        return text if text is None or resource.endswith("$count") else json.loads(text)["d"]

    def ids(self, result):
        return [entity["Id"] for entity in result["results"]]

    def test_paging_and_count(self):
        result = self.query("Products", **{"$orderby": "Name asc", "$skip": "1", "$top": "2",
                                           "$inlinecount": "allpages"})
        self.assertEqual(list(result), ["__count", "results"])
        self.assertEqual(result["__count"], "4")
        # Case-insensitive order, ties in key order
        self.assertEqual(self.ids(result), ["P-2", "P-3"])
        self.assertEqual(self.query("Products/$count"), "4")
        self.assertNotIn("__count", self.query("Products", **{"$top": "1"}))

    def test_order_numbers_and_descending(self):
        self.assertEqual(self.ids(self.query("Products", **{"$orderby": "Price desc"})),
                         ["P-1", "P-3", "P-2", "P-4"])
        self.assertEqual(self.ids(self.query("Products", **{"$orderby": "Category desc,Price asc"})),
                         ["P-4", "P-2", "P-3", "P-1"])

    def test_filters(self):
        def ids(expression):
            return self.ids(self.query("Products", **{"$filter": expression}))
        self.assertEqual(ids("Category eq 'Lighting'"), ["P-4"])
        self.assertEqual(ids("Price ge 99.5 and Price lt 300"), ["P-3", "P-2"])
        self.assertEqual(ids("(Category eq 'Lighting' or Id eq 'P-1') and not (Stock ne 5)"),
                         ["P-1", "P-4"])
        self.assertEqual(ids("substringof('chair',Name)"), ["P-3", "P-2"])
        self.assertEqual(ids("Supplier/Name eq 'Lights Inc'"), ["P-4"])
        self.assertEqual(ids("Supplier eq null"), ["P-3", "P-1", "P-2"])
        # Integer properties compare with rounded numbers
        self.assertEqual(ids("Stock gt 4.5"), [])
        self.assertEqual(ids("Stock gt 4.4"), ["P-3", "P-1", "P-2", "P-4"])
        # Parentheses nest without limit
        self.assertEqual(ids("(" * 500 + "Id eq 'P-1'" + ")" * 500), ["P-1"])

    def test_filter_errors(self):
        def error(expression):
            return self.error("Products", **{"$filter": expression})
        self.assertEqual(error("Name eq"), (400, "Expression expected after position 7"))
        self.assertEqual(error("Name eq 'x' )"), (400, "Invalid token detected at position 13"))
        self.assertEqual(error("Name eq 'x"), (400, "Invalid token detected at position 8"))
        self.assertEqual(error("(Name eq 'x'"), (400, "Expected token ) not found"))
        self.assertEqual(error("()"), (400, "Empty filter expression (Position: 1)"))
        self.assertEqual(error("Name gt 5"),
                         (400, "Invalid parametertype used at function 'gt' (Position: 6)"))
        self.assertEqual(error("not Name eq 'x'"),
                         (400, "Invalid parametertype used at function 'not' (Position: 1)"))
        self.assertEqual(error("Name EQ 'x'"),
                         (400, "Invalid parametertype used at function '' (Position: 6)"))
        self.assertEqual(error("Name"), (400, "Invalid type for '$filter' system query option. "
                                              "Expected type is 'Edm.Boolean'"))
        self.assertEqual(error("Nope eq 1"), (400, "Property Nope not found in type Product"))
        self.assertEqual(error("Supplier/Nope eq 1"),
                         (400, "Property Nope not found in type Supplier"))
        self.assertEqual(error("bogus(Name)"), (400, "Property bogus not found in type Product"))
        self.assertEqual(error("substringof(Name)"),
                         (400, "Too few parameters for function 'substringof'"))
        self.assertEqual(error("tolower(Name,Name) eq 'x'"),
                         (400, "Too many parameters for function 'tolower'"))
        self.assertEqual(error("tolower(Name) eq 'x'"), (400, "Function tolower is not supported"))
        self.assertEqual(error("Favorite"), (400, "Filter condition is not supported - valid"))
        self.assertEqual(error("Name eq Category")[0], 501)
        self.assertEqual(error("not " * 200 + "Favorite")[0], 500)

    def test_option_errors(self):
        self.assertEqual(self.error("Products", **{"$skip": "x"}),
                         (400, "Invalid system query options value"))
        self.assertEqual(self.error("Products", **{"$top": "2147483648"}),
                         (400, "Invalid system query options value"))
        self.assertEqual(self.error("Products", **{"$inlinecount": "some"}),
                         (400, "Invalid system query options value"))
        self.assertEqual(self.error("Products", **{"$orderby": "Name up"}),
                         (400, "Invalid sortorder 'up' detected"))
        self.assertEqual(self.error("Products", **{"$orderby": "Nope"}),
                         (400, "Property Nope not found in type Product"))
        self.assertEqual(self.error("Products", **{"$orderby": "Supplier"})[0], 500)
        self.assertEqual(self.error("Products", **{"$select": "Nope"}),
                         (404, "Resource not found for the segment 'Nope'."))
        self.assertEqual(self.error("Products", **{"$expand": "Supplier/Nope"}),
                         (404, "Resource not found for the segment 'Nope'."))
        self.assertEqual(self.error("Products", **{"$select": "Name,"})[0], 400)
        self.assertEqual(self.error("Products('P-9')"),
                         (404, "Resource not found for segment 'Product'"))
        self.assertEqual(self.error("Products('P-9')/Nope"),
                         (404, "Resource not found for the segment 'Nope'."))
        self.assertEqual(self.error("Products('P-1')/Name"),
                         (404, "Resource not found for segment 'Product'"))
        self.assertEqual(self.query("Products", **{"$top": "", "$filter": ""})["results"][0]["Id"],
                         "P-3")

    def test_hostile_queries_do_not_crash(self):
        """Random token soup gives an answer or an ODataError, nothing else"""
        words = ["Name", "Price", "Stock", "Supplier/Name", "Reviews", "eq", "ne", "gt", "and",
                 "or", "not", "(", ")", ",", "'x'", "''", "'", "1", "1.5", "-2", "null", "true",
                 "substringof", "startswith", "tolower", "guid'0a71'", "datetime'2020'", "@",
                 "EQ", "$", "/", "Nope", "*", "desc", " "]
        generator = random.Random(4103)
        for _ in range(3000):
            text = " ".join(generator.choice(words) for _ in range(generator.randint(1, 12)))
            option = generator.choice(["$filter", "$orderby", "$select", "$expand", "$top"])
            try:
                result = self.store.query(SERVICE, "Products", {option: text})
            except ODataError as error:
                self.assertIn(error.status, (400, 404, 500, 501))
            else:
                self.assertTrue(result is None or isinstance(result, str))

    def test_select_expand_and_serialization(self):
        text = self.store.query(SERVICE, "Products", {"$select": "Id,Changed,Reviews/Rating",
                                                      "$expand": "Reviews", "$top": "1"})
        self.assertIn('"Changed":"\\/Date(1590728742000)\\/"', text)
        entity = json.loads(text)["d"]["results"][0]
        self.assertEqual(list(entity), ["__metadata", "Id", "Changed", "Reviews"])
        # Expanded collections in key order
        self.assertEqual([review["Rating"] for review in entity["Reviews"]["results"]], [2, 4])
        entity = self.query("Products('P-4')")
        self.assertEqual(entity["Supplier"], {"__deferred": {"uri": ROOT + "Products('P-4')/Supplier"}})
        self.assertEqual(entity["Reviews"], {"__deferred": {"uri": ROOT + "Products('P-4')/Reviews"}})
        self.assertIn("°", self.store.query(SERVICE, "Products('P-4')", {}))
        # A null navigation is deferred unless expanded
        self.assertEqual(self.query("Products('P-1')", **{"$expand": "Supplier"})["Supplier"], None)
        self.assertIn("__deferred", self.query("Products('P-1')")["Supplier"])

    def test_keys_and_navigation(self):
        self.assertEqual(self.query("Products(Id='P-2')")["Name"], "Beta Chair")
        reviews = self.query("Products('P-3')/Reviews", **{"$orderby": "Rating desc",
                                                           "$inlinecount": "allpages"})
        self.assertEqual((reviews["__count"], reviews["results"][0]["Rating"]), ("2", 4))
        self.assertEqual(self.query("Products('P-4')/Supplier")["Name"], "Lights Inc")
        self.assertIsNone(self.query("Orders"))

    def test_largest_recording_is_kept(self):
        self.store.add(SERVICE, "Products", json.dumps({"d": {"results": PRODUCTS[:1]}}).encode())
        self.assertEqual(self.query("Products/$count"), "4")
        self.store.add(SERVICE, "Other", b"not json")
        self.assertIsNone(self.query("Other"))

    def test_without_metadata(self):
        """Names come from the recordings; types are not checked"""
        store = EntityStore()
        store.add(SERVICE, "Products", json.dumps({"d": {"results": PRODUCTS}}).encode(),
                  "Reviews,Supplier")
        self.assertEqual(json.loads(store.query(SERVICE, "Products", {"$filter": "Name gt 5"}))
                         ["d"]["results"], [])
        with self.assertRaises(ODataError):
            store.query(SERVICE, "Products", {"$filter": "Nope eq 1"})
        self.assertIsNotNone(FilterParser("Name eq 'x'").parse())
