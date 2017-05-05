import logging
import requests
import json


class PassiveTotal(object):

    base_url = "https://www.passivetotal.org/api"

    api_versions = {"v1": "/v1",
                    "current": "/current"}

    GET_resources = {"metadata": "/metadata",
                     "passive": "/passive",
                     "subdomains": "/subdomains",
                     "tags": "/user/tags",
                     "watch_status": "/watching",
                     "compromise_status": "/ever_compromised",
                     "dynamic_status": "/dynamic",
                     "sinkhole_status": "/sinkhole",
                     "classification": "/classification",
                     "ssl_cert_by_ip": "/ssl_certificate/ip_address",
                     "ssl_cert_by_hash": "/ssl_certificate/hash"}

    POST_resources = {"set_dynamic_status": "/dynamic",
                      "set_watch_status": "/watching",
                      "set_compromise_status": "/ever_compromised",
                      "add_tag": "/user/tag/add",
                      "remove_tag": "/user/tag/remove",
                      "set_classification": "/classification",
                      "set_sinkhole_status": "/sinkhole"}

    def __init__(self, api_key, api_version=None):

        self.__key = api_key

        if api_version:
            try:
                self.api_version = self.api_versions[api_version]
            except KeyError:
                logging.warning("Unrecognized API version, defaulting to v1")
                self.api_version = self.api_versions["v1"]
        else:
            self.api_version = self.api_versions["v1"]

    def retrieve_data(self, query, resource):

        if self.__key:
            try:
                api_call = self.GET_resources[resource]
                url = self.base_url + self.api_version + api_call
                params = {"api_key": self.__key, "query": query}
                response = requests.get(url, params=params)
                json_response = json.loads(response.content)
                return json_response

            except KeyError:
                logging.warning("Unrecognized API resource or malformed query")

        return []

    def submit_data(self, query, resource):

        if self.__key:
            try:
                api_call = self.POST_resources[resource]
                url = self.base_url + self.api_version + api_call
                params = {"api_key": self.__key, "query": query}
                response = requests.post(url, params=params)
                json_response = json.loads(response.content)
                return json_response

            except KeyError:
                logging.warning("Unrecognized API resource or malformed query")

        return []
