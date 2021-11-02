
import unittest
from utils.apis import clean_keys

yandex_example = {
    "Receivers": {
        "ru.yandex.common.clid.ClidBroadcastReceiver": {},
        "ru.yandex.common.session.receivers.BatteryInfoReceiver": {},
        "ru.yandex.common.session.receivers.ConnectivityChangeReceiver": {},
        "ru.yandex.common.session.receivers.DeviceBootReceiver": {},
        "ru.yandex.common.session.receivers.LocaleChangeReceiver": {},
        "ru.yandex.common.session.receivers.PackageEventReceiver": {},                              
    }
}
yandex_expected_result = {
    "Receivers": {
        "ru_yandex_common_clid_ClidBroadcastReceiver": {},
        "ru_yandex_common_session_receivers_BatteryInfoReceiver": {},
        "ru_yandex_common_session_receivers_ConnectivityChangeReceiver": {},
        "ru_yandex_common_session_receivers_DeviceBootReceiver": {},
        "ru_yandex_common_session_receivers_LocaleChangeReceiver": {},
        "ru_yandex_common_session_receivers_PackageEventReceiver": {},                              
    }
}

test_data_example_easy = {"$goodbar...": {}}
counter_example = {"goodkey": {"$$badkey": 123123}}
test_data_example_list = {"$$badbad": [{"morentested...stuff": 123123}, {"blabla": "testest"}]}
test_data_nested_dict = {"hello$$badbad": {"hello...4¤¤$$bad2": {"end_recursion": 123}}}
test_data_nightmare_mode = {
	"$key1": [
		{
			"bad.char": 123, 
			"$$badbad": [{"morentestedstuff": 123123}, {"blabla": "testest"}], 
			"good_key": 123, 
			"goodasdasd": { "$key2recurse": [
				{
					"bad....char": 123, 
					"$$badbad": [{"morentestedstuff": 123123}, {"blabla": "testest"}], 
					"good_key": 123, 
					"goodasdasd": [1,2,3,4,5]
				}
			],
			"$goodbar...": {}}
		}
	],
	"$goodbar...": {},

}
class TestDomainPredictor(unittest.TestCase):

    def test_yandex(self):
        actual_result = clean_keys(yandex_example)
        self.assertEqual(yandex_expected_result, actual_result)
    def test_clean_easy(self):
        expected_result = {"_goodbar___": {}}
        actual_result = clean_keys(test_data_example_easy)
        self.assertEqual(expected_result, actual_result)
    def test_counter_example1(self):
        expected_result = {"goodkey": {"__badkey": 123123}}
        actual = clean_keys(counter_example)
        self.assertEqual(expected_result, actual)

    def test_clean_keys_list(self):
        expected_result = {"__badbad": [{"morentested___stuff": 123123}, {"blabla": "testest"}]}
        actual_result = clean_keys(test_data_example_list)
        self.assertEqual(expected_result, actual_result)

    def test_clean_keys_dict(self):
        expected_result = {"hello__badbad": {"hello___4¤¤__bad2": {"end_recursion": 123}}}
        actual_result = clean_keys(test_data_nested_dict)
        self.assertEqual(expected_result, actual_result)


    def test_clean_keys_nightmare(self):
        expected_result = {
            "_key1": [
                {
                    "bad_char": 123, 
                    "__badbad": [{"morentestedstuff": 123123}, {"blabla": "testest"}], 
                    "good_key": 123, 
                    "goodasdasd": { "_key2recurse": [
                        {
                            "bad____char": 123, 
                            "__badbad": [{"morentestedstuff": 123123}, {"blabla": "testest"}], 
                            "good_key": 123, 
                            "goodasdasd": [1,2,3,4,5]
                        }
                    ],
                    "_goodbar___": {}}
                }
            ],
            "_goodbar___": {},
        }
        actual = clean_keys(test_data_nightmare_mode)
        self.assertEqual(expected_result, actual)
    
if __name__ == '__main__':
    unittest.main()