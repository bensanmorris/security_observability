from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import wrappers_pb2 as _wrappers_pb2
from tetragon import capabilities_pb2 as _capabilities_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class KprobeAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    KPROBE_ACTION_UNKNOWN: _ClassVar[KprobeAction]
    KPROBE_ACTION_POST: _ClassVar[KprobeAction]
    KPROBE_ACTION_FOLLOWFD: _ClassVar[KprobeAction]
    KPROBE_ACTION_SIGKILL: _ClassVar[KprobeAction]
    KPROBE_ACTION_UNFOLLOWFD: _ClassVar[KprobeAction]
    KPROBE_ACTION_OVERRIDE: _ClassVar[KprobeAction]
    KPROBE_ACTION_COPYFD: _ClassVar[KprobeAction]
    KPROBE_ACTION_GETURL: _ClassVar[KprobeAction]
    KPROBE_ACTION_DNSLOOKUP: _ClassVar[KprobeAction]
    KPROBE_ACTION_NOPOST: _ClassVar[KprobeAction]
    KPROBE_ACTION_SIGNAL: _ClassVar[KprobeAction]
    KPROBE_ACTION_TRACKSOCK: _ClassVar[KprobeAction]
    KPROBE_ACTION_UNTRACKSOCK: _ClassVar[KprobeAction]
    KPROBE_ACTION_NOTIFYKILLER: _ClassVar[KprobeAction]

class HealthStatusType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HEALTH_STATUS_TYPE_UNDEF: _ClassVar[HealthStatusType]
    HEALTH_STATUS_TYPE_STATUS: _ClassVar[HealthStatusType]

class HealthStatusResult(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HEALTH_STATUS_UNDEF: _ClassVar[HealthStatusResult]
    HEALTH_STATUS_RUNNING: _ClassVar[HealthStatusResult]
    HEALTH_STATUS_STOPPED: _ClassVar[HealthStatusResult]
    HEALTH_STATUS_ERROR: _ClassVar[HealthStatusResult]

class TaintedBitsType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TAINT_UNSET: _ClassVar[TaintedBitsType]
    TAINT_PROPRIETARY_MODULE: _ClassVar[TaintedBitsType]
    TAINT_FORCED_MODULE: _ClassVar[TaintedBitsType]
    TAINT_FORCED_UNLOAD_MODULE: _ClassVar[TaintedBitsType]
    TAINT_STAGED_MODULE: _ClassVar[TaintedBitsType]
    TAINT_OUT_OF_TREE_MODULE: _ClassVar[TaintedBitsType]
    TAINT_UNSIGNED_MODULE: _ClassVar[TaintedBitsType]
    TAINT_KERNEL_LIVE_PATCH_MODULE: _ClassVar[TaintedBitsType]
    TAINT_TEST_MODULE: _ClassVar[TaintedBitsType]
KPROBE_ACTION_UNKNOWN: KprobeAction
KPROBE_ACTION_POST: KprobeAction
KPROBE_ACTION_FOLLOWFD: KprobeAction
KPROBE_ACTION_SIGKILL: KprobeAction
KPROBE_ACTION_UNFOLLOWFD: KprobeAction
KPROBE_ACTION_OVERRIDE: KprobeAction
KPROBE_ACTION_COPYFD: KprobeAction
KPROBE_ACTION_GETURL: KprobeAction
KPROBE_ACTION_DNSLOOKUP: KprobeAction
KPROBE_ACTION_NOPOST: KprobeAction
KPROBE_ACTION_SIGNAL: KprobeAction
KPROBE_ACTION_TRACKSOCK: KprobeAction
KPROBE_ACTION_UNTRACKSOCK: KprobeAction
KPROBE_ACTION_NOTIFYKILLER: KprobeAction
HEALTH_STATUS_TYPE_UNDEF: HealthStatusType
HEALTH_STATUS_TYPE_STATUS: HealthStatusType
HEALTH_STATUS_UNDEF: HealthStatusResult
HEALTH_STATUS_RUNNING: HealthStatusResult
HEALTH_STATUS_STOPPED: HealthStatusResult
HEALTH_STATUS_ERROR: HealthStatusResult
TAINT_UNSET: TaintedBitsType
TAINT_PROPRIETARY_MODULE: TaintedBitsType
TAINT_FORCED_MODULE: TaintedBitsType
TAINT_FORCED_UNLOAD_MODULE: TaintedBitsType
TAINT_STAGED_MODULE: TaintedBitsType
TAINT_OUT_OF_TREE_MODULE: TaintedBitsType
TAINT_UNSIGNED_MODULE: TaintedBitsType
TAINT_KERNEL_LIVE_PATCH_MODULE: TaintedBitsType
TAINT_TEST_MODULE: TaintedBitsType

class Image(_message.Message):
    __slots__ = ("id", "name")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class Container(_message.Message):
    __slots__ = ("id", "name", "image", "start_time", "pid", "maybe_exec_probe")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    START_TIME_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    MAYBE_EXEC_PROBE_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    image: Image
    start_time: _timestamp_pb2.Timestamp
    pid: _wrappers_pb2.UInt32Value
    maybe_exec_probe: bool
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., image: _Optional[_Union[Image, _Mapping]] = ..., start_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., pid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., maybe_exec_probe: bool = ...) -> None: ...

class Pod(_message.Message):
    __slots__ = ("namespace", "name", "labels", "container", "pod_labels", "workload", "workload_kind")
    class PodLabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    CONTAINER_FIELD_NUMBER: _ClassVar[int]
    POD_LABELS_FIELD_NUMBER: _ClassVar[int]
    WORKLOAD_FIELD_NUMBER: _ClassVar[int]
    WORKLOAD_KIND_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    name: str
    labels: _containers.RepeatedScalarFieldContainer[str]
    container: Container
    pod_labels: _containers.ScalarMap[str, str]
    workload: str
    workload_kind: str
    def __init__(self, namespace: _Optional[str] = ..., name: _Optional[str] = ..., labels: _Optional[_Iterable[str]] = ..., container: _Optional[_Union[Container, _Mapping]] = ..., pod_labels: _Optional[_Mapping[str, str]] = ..., workload: _Optional[str] = ..., workload_kind: _Optional[str] = ...) -> None: ...

class Capabilities(_message.Message):
    __slots__ = ("permitted", "effective", "inheritable")
    PERMITTED_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVE_FIELD_NUMBER: _ClassVar[int]
    INHERITABLE_FIELD_NUMBER: _ClassVar[int]
    permitted: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.CapabilitiesType]
    effective: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.CapabilitiesType]
    inheritable: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.CapabilitiesType]
    def __init__(self, permitted: _Optional[_Iterable[_Union[_capabilities_pb2.CapabilitiesType, str]]] = ..., effective: _Optional[_Iterable[_Union[_capabilities_pb2.CapabilitiesType, str]]] = ..., inheritable: _Optional[_Iterable[_Union[_capabilities_pb2.CapabilitiesType, str]]] = ...) -> None: ...

class Namespace(_message.Message):
    __slots__ = ("inum", "is_host")
    INUM_FIELD_NUMBER: _ClassVar[int]
    IS_HOST_FIELD_NUMBER: _ClassVar[int]
    inum: int
    is_host: bool
    def __init__(self, inum: _Optional[int] = ..., is_host: bool = ...) -> None: ...

class Namespaces(_message.Message):
    __slots__ = ("uts", "ipc", "mnt", "pid", "pid_for_children", "net", "time", "time_for_children", "cgroup", "user")
    UTS_FIELD_NUMBER: _ClassVar[int]
    IPC_FIELD_NUMBER: _ClassVar[int]
    MNT_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    PID_FOR_CHILDREN_FIELD_NUMBER: _ClassVar[int]
    NET_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    TIME_FOR_CHILDREN_FIELD_NUMBER: _ClassVar[int]
    CGROUP_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    uts: Namespace
    ipc: Namespace
    mnt: Namespace
    pid: Namespace
    pid_for_children: Namespace
    net: Namespace
    time: Namespace
    time_for_children: Namespace
    cgroup: Namespace
    user: Namespace
    def __init__(self, uts: _Optional[_Union[Namespace, _Mapping]] = ..., ipc: _Optional[_Union[Namespace, _Mapping]] = ..., mnt: _Optional[_Union[Namespace, _Mapping]] = ..., pid: _Optional[_Union[Namespace, _Mapping]] = ..., pid_for_children: _Optional[_Union[Namespace, _Mapping]] = ..., net: _Optional[_Union[Namespace, _Mapping]] = ..., time: _Optional[_Union[Namespace, _Mapping]] = ..., time_for_children: _Optional[_Union[Namespace, _Mapping]] = ..., cgroup: _Optional[_Union[Namespace, _Mapping]] = ..., user: _Optional[_Union[Namespace, _Mapping]] = ...) -> None: ...

class UserNamespace(_message.Message):
    __slots__ = ("level", "uid", "gid", "ns")
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    GID_FIELD_NUMBER: _ClassVar[int]
    NS_FIELD_NUMBER: _ClassVar[int]
    level: _wrappers_pb2.Int32Value
    uid: _wrappers_pb2.UInt32Value
    gid: _wrappers_pb2.UInt32Value
    ns: Namespace
    def __init__(self, level: _Optional[_Union[_wrappers_pb2.Int32Value, _Mapping]] = ..., uid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., gid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., ns: _Optional[_Union[Namespace, _Mapping]] = ...) -> None: ...

class ProcessCredentials(_message.Message):
    __slots__ = ("uid", "gid", "euid", "egid", "suid", "sgid", "fsuid", "fsgid", "securebits", "caps", "user_ns")
    UID_FIELD_NUMBER: _ClassVar[int]
    GID_FIELD_NUMBER: _ClassVar[int]
    EUID_FIELD_NUMBER: _ClassVar[int]
    EGID_FIELD_NUMBER: _ClassVar[int]
    SUID_FIELD_NUMBER: _ClassVar[int]
    SGID_FIELD_NUMBER: _ClassVar[int]
    FSUID_FIELD_NUMBER: _ClassVar[int]
    FSGID_FIELD_NUMBER: _ClassVar[int]
    SECUREBITS_FIELD_NUMBER: _ClassVar[int]
    CAPS_FIELD_NUMBER: _ClassVar[int]
    USER_NS_FIELD_NUMBER: _ClassVar[int]
    uid: _wrappers_pb2.UInt32Value
    gid: _wrappers_pb2.UInt32Value
    euid: _wrappers_pb2.UInt32Value
    egid: _wrappers_pb2.UInt32Value
    suid: _wrappers_pb2.UInt32Value
    sgid: _wrappers_pb2.UInt32Value
    fsuid: _wrappers_pb2.UInt32Value
    fsgid: _wrappers_pb2.UInt32Value
    securebits: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.SecureBitsType]
    caps: Capabilities
    user_ns: UserNamespace
    def __init__(self, uid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., gid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., euid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., egid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., suid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., sgid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., fsuid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., fsgid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., securebits: _Optional[_Iterable[_Union[_capabilities_pb2.SecureBitsType, str]]] = ..., caps: _Optional[_Union[Capabilities, _Mapping]] = ..., user_ns: _Optional[_Union[UserNamespace, _Mapping]] = ...) -> None: ...

class BinaryProperties(_message.Message):
    __slots__ = ("setuid", "setgid")
    SETUID_FIELD_NUMBER: _ClassVar[int]
    SETGID_FIELD_NUMBER: _ClassVar[int]
    setuid: _wrappers_pb2.UInt32Value
    setgid: _wrappers_pb2.UInt32Value
    def __init__(self, setuid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., setgid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ...) -> None: ...

class Process(_message.Message):
    __slots__ = ("exec_id", "pid", "uid", "cwd", "binary", "arguments", "flags", "start_time", "auid", "pod", "docker", "parent_exec_id", "refcnt", "cap", "ns", "tid", "process_credentials", "binary_properties")
    EXEC_ID_FIELD_NUMBER: _ClassVar[int]
    PID_FIELD_NUMBER: _ClassVar[int]
    UID_FIELD_NUMBER: _ClassVar[int]
    CWD_FIELD_NUMBER: _ClassVar[int]
    BINARY_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    START_TIME_FIELD_NUMBER: _ClassVar[int]
    AUID_FIELD_NUMBER: _ClassVar[int]
    POD_FIELD_NUMBER: _ClassVar[int]
    DOCKER_FIELD_NUMBER: _ClassVar[int]
    PARENT_EXEC_ID_FIELD_NUMBER: _ClassVar[int]
    REFCNT_FIELD_NUMBER: _ClassVar[int]
    CAP_FIELD_NUMBER: _ClassVar[int]
    NS_FIELD_NUMBER: _ClassVar[int]
    TID_FIELD_NUMBER: _ClassVar[int]
    PROCESS_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    BINARY_PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    exec_id: str
    pid: _wrappers_pb2.UInt32Value
    uid: _wrappers_pb2.UInt32Value
    cwd: str
    binary: str
    arguments: str
    flags: str
    start_time: _timestamp_pb2.Timestamp
    auid: _wrappers_pb2.UInt32Value
    pod: Pod
    docker: str
    parent_exec_id: str
    refcnt: int
    cap: Capabilities
    ns: Namespaces
    tid: _wrappers_pb2.UInt32Value
    process_credentials: ProcessCredentials
    binary_properties: BinaryProperties
    def __init__(self, exec_id: _Optional[str] = ..., pid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., uid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., cwd: _Optional[str] = ..., binary: _Optional[str] = ..., arguments: _Optional[str] = ..., flags: _Optional[str] = ..., start_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., auid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., pod: _Optional[_Union[Pod, _Mapping]] = ..., docker: _Optional[str] = ..., parent_exec_id: _Optional[str] = ..., refcnt: _Optional[int] = ..., cap: _Optional[_Union[Capabilities, _Mapping]] = ..., ns: _Optional[_Union[Namespaces, _Mapping]] = ..., tid: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., process_credentials: _Optional[_Union[ProcessCredentials, _Mapping]] = ..., binary_properties: _Optional[_Union[BinaryProperties, _Mapping]] = ...) -> None: ...

class ProcessExec(_message.Message):
    __slots__ = ("process", "parent", "ancestors")
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    ANCESTORS_FIELD_NUMBER: _ClassVar[int]
    process: Process
    parent: Process
    ancestors: _containers.RepeatedCompositeFieldContainer[Process]
    def __init__(self, process: _Optional[_Union[Process, _Mapping]] = ..., parent: _Optional[_Union[Process, _Mapping]] = ..., ancestors: _Optional[_Iterable[_Union[Process, _Mapping]]] = ...) -> None: ...

class ProcessExit(_message.Message):
    __slots__ = ("process", "parent", "signal", "status", "time")
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    process: Process
    parent: Process
    signal: str
    status: int
    time: _timestamp_pb2.Timestamp
    def __init__(self, process: _Optional[_Union[Process, _Mapping]] = ..., parent: _Optional[_Union[Process, _Mapping]] = ..., signal: _Optional[str] = ..., status: _Optional[int] = ..., time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class KprobeSock(_message.Message):
    __slots__ = ("family", "type", "protocol", "mark", "priority", "saddr", "daddr", "sport", "dport", "cookie", "state")
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    MARK_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    SADDR_FIELD_NUMBER: _ClassVar[int]
    DADDR_FIELD_NUMBER: _ClassVar[int]
    SPORT_FIELD_NUMBER: _ClassVar[int]
    DPORT_FIELD_NUMBER: _ClassVar[int]
    COOKIE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    family: str
    type: str
    protocol: str
    mark: int
    priority: int
    saddr: str
    daddr: str
    sport: int
    dport: int
    cookie: int
    state: str
    def __init__(self, family: _Optional[str] = ..., type: _Optional[str] = ..., protocol: _Optional[str] = ..., mark: _Optional[int] = ..., priority: _Optional[int] = ..., saddr: _Optional[str] = ..., daddr: _Optional[str] = ..., sport: _Optional[int] = ..., dport: _Optional[int] = ..., cookie: _Optional[int] = ..., state: _Optional[str] = ...) -> None: ...

class KprobeSkb(_message.Message):
    __slots__ = ("hash", "len", "priority", "mark", "saddr", "daddr", "sport", "dport", "proto", "sec_path_len", "sec_path_olen", "protocol", "family")
    HASH_FIELD_NUMBER: _ClassVar[int]
    LEN_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    MARK_FIELD_NUMBER: _ClassVar[int]
    SADDR_FIELD_NUMBER: _ClassVar[int]
    DADDR_FIELD_NUMBER: _ClassVar[int]
    SPORT_FIELD_NUMBER: _ClassVar[int]
    DPORT_FIELD_NUMBER: _ClassVar[int]
    PROTO_FIELD_NUMBER: _ClassVar[int]
    SEC_PATH_LEN_FIELD_NUMBER: _ClassVar[int]
    SEC_PATH_OLEN_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    FAMILY_FIELD_NUMBER: _ClassVar[int]
    hash: int
    len: int
    priority: int
    mark: int
    saddr: str
    daddr: str
    sport: int
    dport: int
    proto: int
    sec_path_len: int
    sec_path_olen: int
    protocol: str
    family: str
    def __init__(self, hash: _Optional[int] = ..., len: _Optional[int] = ..., priority: _Optional[int] = ..., mark: _Optional[int] = ..., saddr: _Optional[str] = ..., daddr: _Optional[str] = ..., sport: _Optional[int] = ..., dport: _Optional[int] = ..., proto: _Optional[int] = ..., sec_path_len: _Optional[int] = ..., sec_path_olen: _Optional[int] = ..., protocol: _Optional[str] = ..., family: _Optional[str] = ...) -> None: ...

class KprobePath(_message.Message):
    __slots__ = ("mount", "path", "flags")
    MOUNT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    mount: str
    path: str
    flags: str
    def __init__(self, mount: _Optional[str] = ..., path: _Optional[str] = ..., flags: _Optional[str] = ...) -> None: ...

class KprobeFile(_message.Message):
    __slots__ = ("mount", "path", "flags")
    MOUNT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    mount: str
    path: str
    flags: str
    def __init__(self, mount: _Optional[str] = ..., path: _Optional[str] = ..., flags: _Optional[str] = ...) -> None: ...

class KprobeTruncatedBytes(_message.Message):
    __slots__ = ("bytes_arg", "orig_size")
    BYTES_ARG_FIELD_NUMBER: _ClassVar[int]
    ORIG_SIZE_FIELD_NUMBER: _ClassVar[int]
    bytes_arg: bytes
    orig_size: int
    def __init__(self, bytes_arg: _Optional[bytes] = ..., orig_size: _Optional[int] = ...) -> None: ...

class KprobeCred(_message.Message):
    __slots__ = ("permitted", "effective", "inheritable")
    PERMITTED_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVE_FIELD_NUMBER: _ClassVar[int]
    INHERITABLE_FIELD_NUMBER: _ClassVar[int]
    permitted: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.CapabilitiesType]
    effective: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.CapabilitiesType]
    inheritable: _containers.RepeatedScalarFieldContainer[_capabilities_pb2.CapabilitiesType]
    def __init__(self, permitted: _Optional[_Iterable[_Union[_capabilities_pb2.CapabilitiesType, str]]] = ..., effective: _Optional[_Iterable[_Union[_capabilities_pb2.CapabilitiesType, str]]] = ..., inheritable: _Optional[_Iterable[_Union[_capabilities_pb2.CapabilitiesType, str]]] = ...) -> None: ...

class KprobeCapability(_message.Message):
    __slots__ = ("value", "name")
    VALUE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    value: _wrappers_pb2.Int32Value
    name: str
    def __init__(self, value: _Optional[_Union[_wrappers_pb2.Int32Value, _Mapping]] = ..., name: _Optional[str] = ...) -> None: ...

class KprobeUserNamespace(_message.Message):
    __slots__ = ("level", "owner", "group", "ns")
    LEVEL_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    GROUP_FIELD_NUMBER: _ClassVar[int]
    NS_FIELD_NUMBER: _ClassVar[int]
    level: _wrappers_pb2.Int32Value
    owner: _wrappers_pb2.UInt32Value
    group: _wrappers_pb2.UInt32Value
    ns: Namespace
    def __init__(self, level: _Optional[_Union[_wrappers_pb2.Int32Value, _Mapping]] = ..., owner: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., group: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ..., ns: _Optional[_Union[Namespace, _Mapping]] = ...) -> None: ...

class KprobeBpfAttr(_message.Message):
    __slots__ = ("ProgType", "InsnCnt", "ProgName")
    PROGTYPE_FIELD_NUMBER: _ClassVar[int]
    INSNCNT_FIELD_NUMBER: _ClassVar[int]
    PROGNAME_FIELD_NUMBER: _ClassVar[int]
    ProgType: str
    InsnCnt: int
    ProgName: str
    def __init__(self, ProgType: _Optional[str] = ..., InsnCnt: _Optional[int] = ..., ProgName: _Optional[str] = ...) -> None: ...

class KprobePerfEvent(_message.Message):
    __slots__ = ("KprobeFunc", "Type", "Config", "ProbeOffset")
    KPROBEFUNC_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_FIELD_NUMBER: _ClassVar[int]
    PROBEOFFSET_FIELD_NUMBER: _ClassVar[int]
    KprobeFunc: str
    Type: str
    Config: int
    ProbeOffset: int
    def __init__(self, KprobeFunc: _Optional[str] = ..., Type: _Optional[str] = ..., Config: _Optional[int] = ..., ProbeOffset: _Optional[int] = ...) -> None: ...

class KprobeBpfMap(_message.Message):
    __slots__ = ("MapType", "KeySize", "ValueSize", "MaxEntries", "MapName")
    MAPTYPE_FIELD_NUMBER: _ClassVar[int]
    KEYSIZE_FIELD_NUMBER: _ClassVar[int]
    VALUESIZE_FIELD_NUMBER: _ClassVar[int]
    MAXENTRIES_FIELD_NUMBER: _ClassVar[int]
    MAPNAME_FIELD_NUMBER: _ClassVar[int]
    MapType: str
    KeySize: int
    ValueSize: int
    MaxEntries: int
    MapName: str
    def __init__(self, MapType: _Optional[str] = ..., KeySize: _Optional[int] = ..., ValueSize: _Optional[int] = ..., MaxEntries: _Optional[int] = ..., MapName: _Optional[str] = ...) -> None: ...

class KprobeArgument(_message.Message):
    __slots__ = ("string_arg", "int_arg", "skb_arg", "size_arg", "bytes_arg", "path_arg", "file_arg", "truncated_bytes_arg", "sock_arg", "cred_arg", "long_arg", "bpf_attr_arg", "perf_event_arg", "bpf_map_arg", "uint_arg", "user_namespace_arg", "capability_arg", "process_credentials_arg", "user_ns_arg", "module_arg", "label")
    STRING_ARG_FIELD_NUMBER: _ClassVar[int]
    INT_ARG_FIELD_NUMBER: _ClassVar[int]
    SKB_ARG_FIELD_NUMBER: _ClassVar[int]
    SIZE_ARG_FIELD_NUMBER: _ClassVar[int]
    BYTES_ARG_FIELD_NUMBER: _ClassVar[int]
    PATH_ARG_FIELD_NUMBER: _ClassVar[int]
    FILE_ARG_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_BYTES_ARG_FIELD_NUMBER: _ClassVar[int]
    SOCK_ARG_FIELD_NUMBER: _ClassVar[int]
    CRED_ARG_FIELD_NUMBER: _ClassVar[int]
    LONG_ARG_FIELD_NUMBER: _ClassVar[int]
    BPF_ATTR_ARG_FIELD_NUMBER: _ClassVar[int]
    PERF_EVENT_ARG_FIELD_NUMBER: _ClassVar[int]
    BPF_MAP_ARG_FIELD_NUMBER: _ClassVar[int]
    UINT_ARG_FIELD_NUMBER: _ClassVar[int]
    USER_NAMESPACE_ARG_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_ARG_FIELD_NUMBER: _ClassVar[int]
    PROCESS_CREDENTIALS_ARG_FIELD_NUMBER: _ClassVar[int]
    USER_NS_ARG_FIELD_NUMBER: _ClassVar[int]
    MODULE_ARG_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    string_arg: str
    int_arg: int
    skb_arg: KprobeSkb
    size_arg: int
    bytes_arg: bytes
    path_arg: KprobePath
    file_arg: KprobeFile
    truncated_bytes_arg: KprobeTruncatedBytes
    sock_arg: KprobeSock
    cred_arg: KprobeCred
    long_arg: int
    bpf_attr_arg: KprobeBpfAttr
    perf_event_arg: KprobePerfEvent
    bpf_map_arg: KprobeBpfMap
    uint_arg: int
    user_namespace_arg: KprobeUserNamespace
    capability_arg: KprobeCapability
    process_credentials_arg: ProcessCredentials
    user_ns_arg: UserNamespace
    module_arg: KernelModule
    label: str
    def __init__(self, string_arg: _Optional[str] = ..., int_arg: _Optional[int] = ..., skb_arg: _Optional[_Union[KprobeSkb, _Mapping]] = ..., size_arg: _Optional[int] = ..., bytes_arg: _Optional[bytes] = ..., path_arg: _Optional[_Union[KprobePath, _Mapping]] = ..., file_arg: _Optional[_Union[KprobeFile, _Mapping]] = ..., truncated_bytes_arg: _Optional[_Union[KprobeTruncatedBytes, _Mapping]] = ..., sock_arg: _Optional[_Union[KprobeSock, _Mapping]] = ..., cred_arg: _Optional[_Union[KprobeCred, _Mapping]] = ..., long_arg: _Optional[int] = ..., bpf_attr_arg: _Optional[_Union[KprobeBpfAttr, _Mapping]] = ..., perf_event_arg: _Optional[_Union[KprobePerfEvent, _Mapping]] = ..., bpf_map_arg: _Optional[_Union[KprobeBpfMap, _Mapping]] = ..., uint_arg: _Optional[int] = ..., user_namespace_arg: _Optional[_Union[KprobeUserNamespace, _Mapping]] = ..., capability_arg: _Optional[_Union[KprobeCapability, _Mapping]] = ..., process_credentials_arg: _Optional[_Union[ProcessCredentials, _Mapping]] = ..., user_ns_arg: _Optional[_Union[UserNamespace, _Mapping]] = ..., module_arg: _Optional[_Union[KernelModule, _Mapping]] = ..., label: _Optional[str] = ...) -> None: ...

class ProcessKprobe(_message.Message):
    __slots__ = ("process", "parent", "function_name", "args", "action", "stack_trace", "policy_name")
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    FUNCTION_NAME_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    RETURN_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    STACK_TRACE_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    process: Process
    parent: Process
    function_name: str
    args: _containers.RepeatedCompositeFieldContainer[KprobeArgument]
    action: KprobeAction
    stack_trace: _containers.RepeatedCompositeFieldContainer[StackTraceEntry]
    policy_name: str
    def __init__(self, process: _Optional[_Union[Process, _Mapping]] = ..., parent: _Optional[_Union[Process, _Mapping]] = ..., function_name: _Optional[str] = ..., args: _Optional[_Iterable[_Union[KprobeArgument, _Mapping]]] = ..., action: _Optional[_Union[KprobeAction, str]] = ..., stack_trace: _Optional[_Iterable[_Union[StackTraceEntry, _Mapping]]] = ..., policy_name: _Optional[str] = ..., **kwargs) -> None: ...

class ProcessTracepoint(_message.Message):
    __slots__ = ("process", "parent", "subsys", "event", "args", "policy_name", "action")
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    SUBSYS_FIELD_NUMBER: _ClassVar[int]
    EVENT_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    process: Process
    parent: Process
    subsys: str
    event: str
    args: _containers.RepeatedCompositeFieldContainer[KprobeArgument]
    policy_name: str
    action: KprobeAction
    def __init__(self, process: _Optional[_Union[Process, _Mapping]] = ..., parent: _Optional[_Union[Process, _Mapping]] = ..., subsys: _Optional[str] = ..., event: _Optional[str] = ..., args: _Optional[_Iterable[_Union[KprobeArgument, _Mapping]]] = ..., policy_name: _Optional[str] = ..., action: _Optional[_Union[KprobeAction, str]] = ...) -> None: ...

class ProcessUprobe(_message.Message):
    __slots__ = ("process", "parent", "path", "symbol", "policy_name")
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    process: Process
    parent: Process
    path: str
    symbol: str
    policy_name: str
    def __init__(self, process: _Optional[_Union[Process, _Mapping]] = ..., parent: _Optional[_Union[Process, _Mapping]] = ..., path: _Optional[str] = ..., symbol: _Optional[str] = ..., policy_name: _Optional[str] = ...) -> None: ...

class KernelModule(_message.Message):
    __slots__ = ("name", "signature_ok", "tainted")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_OK_FIELD_NUMBER: _ClassVar[int]
    TAINTED_FIELD_NUMBER: _ClassVar[int]
    name: str
    signature_ok: _wrappers_pb2.BoolValue
    tainted: _containers.RepeatedScalarFieldContainer[TaintedBitsType]
    def __init__(self, name: _Optional[str] = ..., signature_ok: _Optional[_Union[_wrappers_pb2.BoolValue, _Mapping]] = ..., tainted: _Optional[_Iterable[_Union[TaintedBitsType, str]]] = ...) -> None: ...

class Test(_message.Message):
    __slots__ = ("arg0", "arg1", "arg2", "arg3")
    ARG0_FIELD_NUMBER: _ClassVar[int]
    ARG1_FIELD_NUMBER: _ClassVar[int]
    ARG2_FIELD_NUMBER: _ClassVar[int]
    ARG3_FIELD_NUMBER: _ClassVar[int]
    arg0: int
    arg1: int
    arg2: int
    arg3: int
    def __init__(self, arg0: _Optional[int] = ..., arg1: _Optional[int] = ..., arg2: _Optional[int] = ..., arg3: _Optional[int] = ...) -> None: ...

class GetHealthStatusRequest(_message.Message):
    __slots__ = ("event_set",)
    EVENT_SET_FIELD_NUMBER: _ClassVar[int]
    event_set: _containers.RepeatedScalarFieldContainer[HealthStatusType]
    def __init__(self, event_set: _Optional[_Iterable[_Union[HealthStatusType, str]]] = ...) -> None: ...

class HealthStatus(_message.Message):
    __slots__ = ("event", "status", "details")
    EVENT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    event: HealthStatusType
    status: HealthStatusResult
    details: str
    def __init__(self, event: _Optional[_Union[HealthStatusType, str]] = ..., status: _Optional[_Union[HealthStatusResult, str]] = ..., details: _Optional[str] = ...) -> None: ...

class GetHealthStatusResponse(_message.Message):
    __slots__ = ("health_status",)
    HEALTH_STATUS_FIELD_NUMBER: _ClassVar[int]
    health_status: _containers.RepeatedCompositeFieldContainer[HealthStatus]
    def __init__(self, health_status: _Optional[_Iterable[_Union[HealthStatus, _Mapping]]] = ...) -> None: ...

class ProcessLoader(_message.Message):
    __slots__ = ("process", "path", "buildid")
    PROCESS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    BUILDID_FIELD_NUMBER: _ClassVar[int]
    process: Process
    path: str
    buildid: bytes
    def __init__(self, process: _Optional[_Union[Process, _Mapping]] = ..., path: _Optional[str] = ..., buildid: _Optional[bytes] = ...) -> None: ...

class RuntimeHookRequest(_message.Message):
    __slots__ = ("createContainer",)
    CREATECONTAINER_FIELD_NUMBER: _ClassVar[int]
    createContainer: CreateContainer
    def __init__(self, createContainer: _Optional[_Union[CreateContainer, _Mapping]] = ...) -> None: ...

class RuntimeHookResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CreateContainer(_message.Message):
    __slots__ = ("cgroupsPath", "rootDir", "annotations")
    class AnnotationsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    CGROUPSPATH_FIELD_NUMBER: _ClassVar[int]
    ROOTDIR_FIELD_NUMBER: _ClassVar[int]
    ANNOTATIONS_FIELD_NUMBER: _ClassVar[int]
    cgroupsPath: str
    rootDir: str
    annotations: _containers.ScalarMap[str, str]
    def __init__(self, cgroupsPath: _Optional[str] = ..., rootDir: _Optional[str] = ..., annotations: _Optional[_Mapping[str, str]] = ...) -> None: ...

class StackTraceEntry(_message.Message):
    __slots__ = ("address", "offset", "symbol")
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SYMBOL_FIELD_NUMBER: _ClassVar[int]
    address: int
    offset: int
    symbol: str
    def __init__(self, address: _Optional[int] = ..., offset: _Optional[int] = ..., symbol: _Optional[str] = ...) -> None: ...
