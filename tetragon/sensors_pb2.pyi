from tetragon import tetragon_pb2 as _tetragon_pb2
from tetragon import stack_pb2 as _stack_pb2
from tetragon import events_pb2 as _events_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ListSensorsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SensorStatus(_message.Message):
    __slots__ = ("name", "enabled", "collection")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    COLLECTION_FIELD_NUMBER: _ClassVar[int]
    name: str
    enabled: bool
    collection: str
    def __init__(self, name: _Optional[str] = ..., enabled: bool = ..., collection: _Optional[str] = ...) -> None: ...

class ListSensorsResponse(_message.Message):
    __slots__ = ("sensors",)
    SENSORS_FIELD_NUMBER: _ClassVar[int]
    sensors: _containers.RepeatedCompositeFieldContainer[SensorStatus]
    def __init__(self, sensors: _Optional[_Iterable[_Union[SensorStatus, _Mapping]]] = ...) -> None: ...

class ListTracingPoliciesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class TracingPolicyStatus(_message.Message):
    __slots__ = ("id", "name", "namespace", "info", "sensors", "enabled", "filter_id", "error")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    INFO_FIELD_NUMBER: _ClassVar[int]
    SENSORS_FIELD_NUMBER: _ClassVar[int]
    ENABLED_FIELD_NUMBER: _ClassVar[int]
    FILTER_ID_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    id: int
    name: str
    namespace: str
    info: str
    sensors: _containers.RepeatedScalarFieldContainer[str]
    enabled: bool
    filter_id: int
    error: str
    def __init__(self, id: _Optional[int] = ..., name: _Optional[str] = ..., namespace: _Optional[str] = ..., info: _Optional[str] = ..., sensors: _Optional[_Iterable[str]] = ..., enabled: bool = ..., filter_id: _Optional[int] = ..., error: _Optional[str] = ...) -> None: ...

class ListTracingPoliciesResponse(_message.Message):
    __slots__ = ("policies",)
    POLICIES_FIELD_NUMBER: _ClassVar[int]
    policies: _containers.RepeatedCompositeFieldContainer[TracingPolicyStatus]
    def __init__(self, policies: _Optional[_Iterable[_Union[TracingPolicyStatus, _Mapping]]] = ...) -> None: ...

class AddTracingPolicyRequest(_message.Message):
    __slots__ = ("yaml",)
    YAML_FIELD_NUMBER: _ClassVar[int]
    yaml: str
    def __init__(self, yaml: _Optional[str] = ...) -> None: ...

class AddTracingPolicyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteTracingPolicyRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DeleteTracingPolicyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EnableTracingPolicyRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class EnableTracingPolicyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DisableTracingPolicyRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DisableTracingPolicyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RemoveSensorRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class RemoveSensorResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EnableSensorRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class EnableSensorResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DisableSensorRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class DisableSensorResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetStackTraceTreeRequest(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class GetStackTraceTreeResponse(_message.Message):
    __slots__ = ("root",)
    ROOT_FIELD_NUMBER: _ClassVar[int]
    root: _stack_pb2.StackTraceNode
    def __init__(self, root: _Optional[_Union[_stack_pb2.StackTraceNode, _Mapping]] = ...) -> None: ...

class GetVersionRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetVersionResponse(_message.Message):
    __slots__ = ("version",)
    VERSION_FIELD_NUMBER: _ClassVar[int]
    version: str
    def __init__(self, version: _Optional[str] = ...) -> None: ...
