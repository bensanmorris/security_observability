from tetragon import tetragon_pb2 as _tetragon_pb2
from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import wrappers_pb2 as _wrappers_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import field_mask_pb2 as _field_mask_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EventType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    UNDEF: _ClassVar[EventType]
    PROCESS_EXEC: _ClassVar[EventType]
    PROCESS_EXIT: _ClassVar[EventType]
    PROCESS_KPROBE: _ClassVar[EventType]
    PROCESS_TRACEPOINT: _ClassVar[EventType]
    PROCESS_LOADER: _ClassVar[EventType]
    PROCESS_UPROBE: _ClassVar[EventType]
    TEST: _ClassVar[EventType]
    RATE_LIMIT_INFO: _ClassVar[EventType]

class FieldFilterAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INCLUDE: _ClassVar[FieldFilterAction]
    EXCLUDE: _ClassVar[FieldFilterAction]
UNDEF: EventType
PROCESS_EXEC: EventType
PROCESS_EXIT: EventType
PROCESS_KPROBE: EventType
PROCESS_TRACEPOINT: EventType
PROCESS_LOADER: EventType
PROCESS_UPROBE: EventType
TEST: EventType
RATE_LIMIT_INFO: EventType
INCLUDE: FieldFilterAction
EXCLUDE: FieldFilterAction

class Filter(_message.Message):
    __slots__ = ("binary_regex", "namespace", "health_check", "pid", "pid_set", "event_set", "pod_regex", "arguments_regex", "labels")
    BINARY_REGEX_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    HEALTH_CHECK_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    PID_SET_FIELD_NUMBER: _ClassVar[int]
    EVENT_SET_FIELD_NUMBER: _ClassVar[int]
    POD_REGEX_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_REGEX_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    binary_regex: _containers.RepeatedScalarFieldContainer[str]
    namespace: _containers.RepeatedScalarFieldContainer[str]
    health_check: _wrappers_pb2.BoolValue
    pid: _containers.RepeatedScalarFieldContainer[int]
    pid_set: _containers.RepeatedScalarFieldContainer[int]
    event_set: _containers.RepeatedScalarFieldContainer[EventType]
    pod_regex: _containers.RepeatedScalarFieldContainer[str]
    arguments_regex: _containers.RepeatedScalarFieldContainer[str]
    labels: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, binary_regex: _Optional[_Iterable[str]] = ..., namespace: _Optional[_Iterable[str]] = ..., health_check: _Optional[_Union[_wrappers_pb2.BoolValue, _Mapping]] = ..., pid: _Optional[_Iterable[int]] = ..., pid_set: _Optional[_Iterable[int]] = ..., event_set: _Optional[_Iterable[_Union[EventType, str]]] = ..., pod_regex: _Optional[_Iterable[str]] = ..., arguments_regex: _Optional[_Iterable[str]] = ..., labels: _Optional[_Iterable[str]] = ...) -> None: ...

class FieldFilter(_message.Message):
    __slots__ = ("event_set", "fields", "action", "invert_event_set")
    EVENT_SET_FIELD_NUMBER: _ClassVar[int]
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    INVERT_EVENT_SET_FIELD_NUMBER: _ClassVar[int]
    event_set: _containers.RepeatedScalarFieldContainer[EventType]
    fields: _field_mask_pb2.FieldMask
    action: FieldFilterAction
    invert_event_set: _wrappers_pb2.BoolValue
    def __init__(self, event_set: _Optional[_Iterable[_Union[EventType, str]]] = ..., fields: _Optional[_Union[_field_mask_pb2.FieldMask, _Mapping]] = ..., action: _Optional[_Union[FieldFilterAction, str]] = ..., invert_event_set: _Optional[_Union[_wrappers_pb2.BoolValue, _Mapping]] = ...) -> None: ...

class GetEventsRequest(_message.Message):
    __slots__ = ("allow_list", "deny_list", "aggregation_options", "field_filters")
    ALLOW_LIST_FIELD_NUMBER: _ClassVar[int]
    DENY_LIST_FIELD_NUMBER: _ClassVar[int]
    AGGREGATION_OPTIONS_FIELD_NUMBER: _ClassVar[int]
    FIELD_FILTERS_FIELD_NUMBER: _ClassVar[int]
    allow_list: _containers.RepeatedCompositeFieldContainer[Filter]
    deny_list: _containers.RepeatedCompositeFieldContainer[Filter]
    aggregation_options: AggregationOptions
    field_filters: _containers.RepeatedCompositeFieldContainer[FieldFilter]
    def __init__(self, allow_list: _Optional[_Iterable[_Union[Filter, _Mapping]]] = ..., deny_list: _Optional[_Iterable[_Union[Filter, _Mapping]]] = ..., aggregation_options: _Optional[_Union[AggregationOptions, _Mapping]] = ..., field_filters: _Optional[_Iterable[_Union[FieldFilter, _Mapping]]] = ...) -> None: ...

class AggregationOptions(_message.Message):
    __slots__ = ("window_size", "channel_buffer_size")
    WINDOW_SIZE_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_BUFFER_SIZE_FIELD_NUMBER: _ClassVar[int]
    window_size: _duration_pb2.Duration
    channel_buffer_size: int
    def __init__(self, window_size: _Optional[_Union[_duration_pb2.Duration, _Mapping]] = ..., channel_buffer_size: _Optional[int] = ...) -> None: ...

class AggregationInfo(_message.Message):
    __slots__ = ("count",)
    COUNT_FIELD_NUMBER: _ClassVar[int]
    count: int
    def __init__(self, count: _Optional[int] = ...) -> None: ...

class RateLimitInfo(_message.Message):
    __slots__ = ("number_of_dropped_process_events",)
    NUMBER_OF_DROPPED_PROCESS_EVENTS_FIELD_NUMBER: _ClassVar[int]
    number_of_dropped_process_events: int
    def __init__(self, number_of_dropped_process_events: _Optional[int] = ...) -> None: ...

class GetEventsResponse(_message.Message):
    __slots__ = ("process_exec", "process_exit", "process_kprobe", "process_tracepoint", "process_loader", "process_uprobe", "test", "rate_limit_info", "node_name", "time", "aggregation_info")
    PROCESS_EXEC_FIELD_NUMBER: _ClassVar[int]
    PROCESS_EXIT_FIELD_NUMBER: _ClassVar[int]
    PROCESS_KPROBE_FIELD_NUMBER: _ClassVar[int]
    PROCESS_TRACEPOINT_FIELD_NUMBER: _ClassVar[int]
    PROCESS_LOADER_FIELD_NUMBER: _ClassVar[int]
    PROCESS_UPROBE_FIELD_NUMBER: _ClassVar[int]
    TEST_FIELD_NUMBER: _ClassVar[int]
    RATE_LIMIT_INFO_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    AGGREGATION_INFO_FIELD_NUMBER: _ClassVar[int]
    process_exec: _tetragon_pb2.ProcessExec
    process_exit: _tetragon_pb2.ProcessExit
    process_kprobe: _tetragon_pb2.ProcessKprobe
    process_tracepoint: _tetragon_pb2.ProcessTracepoint
    process_loader: _tetragon_pb2.ProcessLoader
    process_uprobe: _tetragon_pb2.ProcessUprobe
    test: _tetragon_pb2.Test
    rate_limit_info: RateLimitInfo
    node_name: str
    time: _timestamp_pb2.Timestamp
    aggregation_info: AggregationInfo
    def __init__(self, process_exec: _Optional[_Union[_tetragon_pb2.ProcessExec, _Mapping]] = ..., process_exit: _Optional[_Union[_tetragon_pb2.ProcessExit, _Mapping]] = ..., process_kprobe: _Optional[_Union[_tetragon_pb2.ProcessKprobe, _Mapping]] = ..., process_tracepoint: _Optional[_Union[_tetragon_pb2.ProcessTracepoint, _Mapping]] = ..., process_loader: _Optional[_Union[_tetragon_pb2.ProcessLoader, _Mapping]] = ..., process_uprobe: _Optional[_Union[_tetragon_pb2.ProcessUprobe, _Mapping]] = ..., test: _Optional[_Union[_tetragon_pb2.Test, _Mapping]] = ..., rate_limit_info: _Optional[_Union[RateLimitInfo, _Mapping]] = ..., node_name: _Optional[str] = ..., time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., aggregation_info: _Optional[_Union[AggregationInfo, _Mapping]] = ...) -> None: ...
