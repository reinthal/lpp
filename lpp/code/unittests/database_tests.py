import unittest
from utils.database import SetupDatabase

ALERTS_TESTS="alerts_tests"
DOMAINS_TESTS="domains_tests"

class TestDatabase(unittest.TestCase):

    def setUp(self) -> None:
        self.database = SetupDatabase()
        self.database.db[ALERTS_TESTS].update_many({}, {"$unset": {"hosts_array": ""}})
        return super().setUp()

    def test_create_hosts_array(self):
        self.database.create_hosts_array(collection=ALERTS_TESTS)
        nr_no_hosts_array = self.database.db[ALERTS_TESTS].find({"hosts_array": {"$exists": False}}).count()
        self.assertEqual(nr_no_hosts_array, 0, msg="Some alerts do not have hosts_array field")
        
    
    def test_type_hosts_array(self):
        self.database.create_hosts_array(collection=ALERTS_TESTS)
        nr_hosts_array_not_array = self.database.db[ALERTS_TESTS].find({"hosts_array": {"$not": {"$type" : "array"}}}).count()
        self.assertEqual(nr_hosts_array_not_array, 0, msg="Some alerts have hosts_array that aren't arrays")

if __name__ == '__main__':
    unittest.main()