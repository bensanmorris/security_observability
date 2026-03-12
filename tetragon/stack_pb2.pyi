from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class StackAddress(_message.Message):
    __slots__ = ("address", "symbol")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    address: int
    symbol: str
    def __init__(self, address: _Optional[int] = ..., symbol: _Optional[str] = ...) -> None: ...

class StackTrace(_message.Message):
    __slots__ = ("addresses",)
    ADDRESSES_FIELD_NUMBER: _ClassVar[int]
    addresses: _containers.RepeatedCompositeFieldContainer[StackAddress]
    def __init__(self, addresses: _Optional[_Iterable[_Union[StackAddress, _Mapping]]] = ...) -> None: ...

class StackTraceLabel(_message.Message):
    __slots__ = ("key", "count")
    KEY_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    key: str
    count: int
    def __init__(self, key: _Optional[str] = ..., count: _Optional[int] = ...) -> None: ...

class StackTraceNode(_message.Message):
    __slots__ = ("address", "count", "labels", "children")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CHILDREN_FIELD_NUMBER: _ClassVar[int]
    address: StackAddress
    count: int
    labels: _containers.RepeatedCompositeFieldContainer[StackTraceLabel]
    children: _containers.RepeatedCompositeFieldContainer[StackTraceNode]
    def __init__(self, address: _Optional[_Union[StackAddress, _Mapping]] = ..., count: _Optional[int] = ..., labels: _Optional[_Iterable[_Union[StackTraceLabel, _Mapping]]] = ..., children: _Optional[_Iterable[_Union[StackTraceNode, _Mapping]]] = ...) -> None: ...
