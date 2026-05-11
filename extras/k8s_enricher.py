"""
Kubernetes Pod Enrichment for cert-analyzer
Enriches Tetragon events with full Kubernetes workload context:
  - Pod name, namespace, labels
  - Owning workload (Deployment, DaemonSet, StatefulSet)
  - Container name and image

Requires the cert-analyzer pod to have a ServiceAccount with permission
to GET and LIST pods in the namespaces being monitored (see rbac.yaml).
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass
class PodContext:
    """Full Kubernetes workload context for a certificate access event"""
    pod_name: str = ""
    namespace: str = ""
    node_name: str = ""
    # The app label - most workloads set one of these
    app_label: str = ""
    # Raw labels dict for anything else you want to surface
    labels: dict = field(default_factory=dict)
    # Owning workload e.g. "Deployment/payments-api"
    workload_kind: str = ""
    workload_name: str = ""
    # Container that triggered the event
    container_name: str = ""
    container_image: str = ""

    @property
    def workload(self) -> str:
        """Human-readable workload reference e.g. Deployment/payments-api"""
        if self.workload_kind and self.workload_name:
            return f"{self.workload_kind}/{self.workload_name}"
        return ""

    @property
    def summary(self) -> str:
        """One-line summary suitable for log output"""
        parts = [f"pod={self.pod_name}", f"namespace={self.namespace}"]
        if self.workload:
            parts.append(f"workload={self.workload}")
        if self.container_name:
            parts.append(f"container={self.container_name}")
        return " ".join(parts)


class KubernetesEnricher:
    """
    Looks up Kubernetes pod metadata by pod name + namespace and resolves
    the owning workload by walking ownerReferences up the chain.

    Results are cached to avoid hammering the API on repeated events for
    the same pod. Cache is intentionally short-lived (TTL via lru_cache
    size limit) since pods can be replaced by rolling deployments.
    """

    def __init__(self):
        self._client = None
        self._core_v1 = None
        self._apps_v1 = None
        self._available = False
        self._init_client()

    def _init_client(self):
        """Initialise the Kubernetes client - works both in-cluster and locally"""
        try:
            from kubernetes import client, config

            try:
                # Running inside a pod - use the mounted service account token
                config.load_incluster_config()
                logger.info("Kubernetes enricher: loaded in-cluster config")
            except Exception:
                # Running locally - use ~/.kube/config
                config.load_kube_config()
                logger.info("Kubernetes enricher: loaded local kubeconfig")

            self._core_v1 = client.CoreV1Api()
            self._apps_v1 = client.AppsV1Api()
            self._available = True

        except ImportError:
            logger.warning(
                "kubernetes Python package not installed - pod enrichment disabled. "
                "Install with: pip install kubernetes"
            )
        except Exception as e:
            logger.warning(f"Kubernetes enricher unavailable: {e}")

    @property
    def available(self) -> bool:
        return self._available

    def enrich(self, pod_name: str, namespace: str) -> Optional[PodContext]:
        """
        Look up a pod and return its full workload context.
        Returns None if the pod cannot be found or the API is unavailable.
        """
        if not self._available or not pod_name or not namespace:
            return None

        try:
            return self._get_pod_context(pod_name, namespace)
        except Exception as e:
            logger.debug(f"Pod enrichment failed for {namespace}/{pod_name}: {e}")
            return None

    @lru_cache(maxsize=512)
    def _get_pod_context(self, pod_name: str, namespace: str) -> Optional[PodContext]:
        """Cached pod lookup - cache key is (pod_name, namespace)"""
        from kubernetes.client.exceptions import ApiException

        try:
            pod = self._core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        except ApiException as e:
            if e.status == 404:
                logger.debug(f"Pod not found: {namespace}/{pod_name}")
            else:
                logger.warning(f"API error looking up pod {namespace}/{pod_name}: {e}")
            return None

        ctx = PodContext(
            pod_name=pod_name,
            namespace=namespace,
            node_name=pod.spec.node_name or "",
            labels=pod.metadata.labels or {},
        )

        # Resolve a friendly app label - try common conventions in order
        for label_key in ["app.kubernetes.io/name", "app", "name"]:
            if label_key in ctx.labels:
                ctx.app_label = ctx.labels[label_key]
                break

        # Resolve owning workload by walking ownerReferences
        workload_kind, workload_name = self._resolve_workload(pod, namespace)
        ctx.workload_kind = workload_kind
        ctx.workload_name = workload_name

        # Pick the first container as a best-effort (Tetragon events don't
        # always identify the specific container)
        if pod.spec.containers:
            ctx.container_name = pod.spec.containers[0].name
            ctx.container_image = pod.spec.containers[0].image or ""

        return ctx

    def _resolve_workload(self, pod, namespace: str):
        """
        Walk ownerReferences to find the top-level workload.
        Pod → ReplicaSet → Deployment is the common chain for Deployments.
        Pod → DaemonSet / StatefulSet / Job are direct single-hop references.
        """
        refs = pod.metadata.owner_references or []
        if not refs:
            return "", ""

        ref = refs[0]
        kind = ref.kind
        name = ref.name

        # ReplicaSet is an intermediate owner - walk up to the Deployment
        if kind == "ReplicaSet":
            try:
                rs = self._apps_v1.read_namespaced_replica_set(name=name, namespace=namespace)
                rs_refs = rs.metadata.owner_references or []
                if rs_refs and rs_refs[0].kind == "Deployment":
                    return "Deployment", rs_refs[0].name
            except Exception as e:
                logger.debug(f"Could not resolve ReplicaSet owner: {e}")

        # DaemonSet, StatefulSet, Job etc. are direct owners
        return kind, name

