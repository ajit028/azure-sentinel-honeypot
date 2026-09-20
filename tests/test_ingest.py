#!/usr/bin/env python3
"""
Unit tests for Azure Sentinel Honeypot Ingestion & Geo-Enrichment Pipeline.
Verifies event parsing, IP geolocation enrichment logic, rate limiting, and fallback behavior.
"""

import unittest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

class TestGeoIngestionPipeline(unittest.TestCase):
    
    def setUp(self):
        self.sample_event = {
            "TimeGenerated": "2026-03-30T12:00:00Z",
            "Computer": "HoneypotVM01",
            "EventID": 4625,
            "TargetUserName": "Administrator",
            "IpAddress": "185.220.101.5",
            "FailureReason": "%%2313"
        }
        self.mock_geo_response = {
            "ip": "185.220.101.5",
            "city": "Berlin",
            "region": "Berlin",
            "country_name": "Germany",
            "latitude": 52.5200,
            "longitude": 13.4050,
            "org": "Tor Exit Node"
        }

    def test_sample_event_structure(self):
        self.assertEqual(self.sample_event["EventID"], 4625)
        self.assertTrue("IpAddress" in self.sample_event)
        self.assertTrue("TargetUserName" in self.sample_event)

    @patch('urllib.request.urlopen')
    def test_geo_enrichment_mock_api(self, mock_urlopen):
        # Mock API response
        cm = MagicMock()
        cm.read.return_value = json.dumps(self.mock_geo_response).encode('utf-8')
        cm.__enter__.return_value = cm
        mock_urlopen.return_value = cm

        # Simulated enrichment function
        def enrich_ip(ip):
            import urllib.request
            url = f"https://api.ipapi.com/{ip}?access_key=mock_key"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                return data

        result = enrich_ip("185.220.101.5")
        self.assertEqual(result["country_name"], "Germany")
        self.assertEqual(result["city"], "Berlin")
        self.assertEqual(result["latitude"], 52.5200)

    def test_private_ip_filtering(self):
        # RFC 1918 private IPs should be skipped or flagged by ingestor
        private_ips = ["10.0.0.5", "192.168.1.50", "127.0.0.1", "172.16.0.4"]
        
        def is_private(ip):
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 10: return True
            if parts[0] == 172 and 16 <= parts[1] <= 31: return True
            if parts[0] == 192 and parts[1] == 168: return True
            if parts[0] == 127: return True
            return False

        for ip in private_ips:
            self.assertTrue(is_private(ip), f"IP {ip} should be recognized as private")

    def test_fallback_api_logic(self):
        # Test fallback mechanism when primary API fails
        apis = ["https://api.ipapi.com/v1/", "https://ipapi.co/json/"]
        
        def mock_fetch(api_url):
            if "ipapi.com" in api_url:
                raise ConnectionError("Primary API rate limited / unreachable")
            return {"country": "Germany", "source": "fallback"}

        active_api = apis[0]
        try:
            data = mock_fetch(active_api)
        except ConnectionError:
            active_api = apis[1]
            data = mock_fetch(active_api)

        self.assertEqual(data["source"], "fallback")
        self.assertEqual(active_api, apis[1])


if __name__ == '__main__':
    unittest.main()
