"""
pytest configuration and fixtures
Mocks Tetragon protobuf modules for testing
"""

import sys
from unittest.mock import MagicMock

# Mock Tetragon protobuf modules before any imports
mock_tetragon = MagicMock()
mock_tetragon_pb2 = MagicMock()
mock_events_pb2 = MagicMock()
mock_sensors_pb2_grpc = MagicMock()

# Set up the mock module structure
sys.modules['tetragon'] = mock_tetragon
sys.modules['tetragon.tetragon_pb2'] = mock_tetragon_pb2
sys.modules['tetragon.events_pb2'] = mock_events_pb2
sys.modules['tetragon.sensors_pb2_grpc'] = mock_sensors_pb2_grpc

# Make the mocks available as attributes
mock_tetragon.tetragon_pb2 = mock_tetragon_pb2
mock_tetragon.events_pb2 = mock_events_pb2
mock_tetragon.sensors_pb2_grpc = mock_sensors_pb2_grpc

# Add commonly used constants/classes
mock_events_pb2.PROCESS_KPROBE = MagicMock()
mock_events_pb2.PROCESS_UPROBE = MagicMock()
mock_events_pb2.GetEventsRequest = MagicMock()
mock_events_pb2.Filter = MagicMock()
mock_sensors_pb2_grpc.FineGuidanceSensorsStub = MagicMock()
