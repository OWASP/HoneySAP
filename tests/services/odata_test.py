# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

# Standard imports
import json
import unittest
# Custom imports
from honeysap.services.icm.odata import EntityStore, FilterParser, QueryError


ROOT = "https://{{AUTHORITY}}/sap/opu/odata/sap/SHOP/"
SERVICE = "/sap/opu/odata/sap/SHOP/"


def product(key, name, price, category, reviews, supplier=None):
    uri = ROOT + "Products('%s')" % key
    return {"__metadata": {"id": uri, "uri": uri, "type": "SHOP.Product"},
            "Id": key, "Name": name, "Price": price, "Category": category,
            "Changed": "/Date(1590728742000)/", "Stock": 5,
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
        self.assertIsNone(self.query("Products", **{"$filter": "Name eq"}))
        with self.assertRaises(QueryError):
            FilterParser("Name eq 'x' )").parse()

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
        self.assertIsNone(self.query("Products('P-9')"))
        reviews = self.query("Products('P-3')/Reviews", **{"$orderby": "Rating desc",
                                                           "$inlinecount": "allpages"})
        self.assertEqual((reviews["__count"], reviews["results"][0]["Rating"]), ("2", 4))
        self.assertEqual(self.query("Products('P-4')/Supplier")["Name"], "Lights Inc")
        self.assertIsNone(self.query("Orders"))
        self.assertIsNone(self.query("Products", **{"$skip": "x"}))

    def test_largest_recording_is_kept(self):
        self.store.add(SERVICE, "Products", json.dumps({"d": {"results": PRODUCTS[:1]}}).encode())
        self.assertEqual(self.query("Products/$count"), "4")
        self.store.add(SERVICE, "Other", b"not json")
        self.assertIsNone(self.query("Other"))
