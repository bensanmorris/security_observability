# openshift-soak

Container-based counterpart to [`probe_tests/test_large_cert_bundle.py`](../test_large_cert_bundle.py)
for soak-testing the cert-analyzer DaemonSet on OpenShift. Same scenario —
generate a large cert bundle to exercise the background-parsing path, an
immediate canary to prove the event-consumer thread stays unblocked, and an
optional burst of distinct processes re-accessing the cached bundle to
exercise the `tls_certificate_process_info` fan-out cap — but driven from a
Job running on-cluster instead of a script on your own machine.

See [`extras/OPENSHIFT-DEPLOYMENT-README.md`](../../extras/OPENSHIFT-DEPLOYMENT-README.md)
for why this can't just be the bare-metal script pointed at a remote cluster:
`oc debug node` is too slow to drive a realistic parallel-process burst, and a
multi-hour soak shouldn't depend on this machine staying connected.

## How it works

- `soak_test.py` writes its bundle/canary files into `--out-dir` (default
  `/etc/pki/tls/certs`), which `job.yaml` mounts as a `hostPath` volume from
  the node's real filesystem — the same directory cert-analyzer's own
  `CERT_SCAN_PATHS`/`HOST_PREFIX` setup already scans, so both the real-time
  Tetragon `fd_install` kprobe and cert-analyzer's periodic scan see the
  writes exactly as they would from any other process on that node.
- The parallel-process re-access burst spawns real distinct processes
  (copies of `/bin/cat`) *from inside this container* — no per-accessor
  `oc debug node` overhead, so the burst is actually near-simultaneous.
- `--duration` lets an unattended soak run exit cleanly after N seconds
  instead of relying on Ctrl-C.

## Build and push

From the repository root:

```bash
podman build -t cert-soak-test:latest probe_tests/openshift-soak/

HOST=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}')
sudo podman login -u kubeadmin -p "$(oc whoami -t)" --tls-verify=false "$HOST"
sudo podman tag cert-soak-test:latest "$HOST/certsight/cert-soak-test:latest"
sudo podman push --tls-verify=false "$HOST/certsight/cert-soak-test:latest"
```

If you're iterating on `soak_test.py`, push under a fresh tag rather than
re-pushing `:latest` and re-running the Job — `imagePullPolicy: IfNotPresent`
means a stale local image on the node won't be replaced just because the
registry content changed under the same tag. See "Rebuilding and redeploying
after a code change" in `extras/OPENSHIFT-DEPLOYMENT-README.md` for the full
explanation; the short version is `oc set image` (for a Deployment/DaemonSet)
or, for a one-shot Job, just edit `job.yaml`'s `image:` field to the new tag
before creating it.

## Run

```bash
oc apply -f probe_tests/openshift-soak/job.yaml
oc logs -n certsight -l job-name=cert-soak-test -f
```

Adjust the soak parameters by editing `job.yaml`'s `args:` (or delete and
re-apply with different values):

| Arg | Meaning |
|---|---|
| `--count` | certs per generated bundle |
| `--parallel-processes` | distinct re-accessing processes per iteration (0 = skip this check) |
| `--loop-interval` | seconds between iterations |
| `--duration` | total soak wall-clock time before exiting cleanly |

## Verify

While the Job runs, watch the cert-analyzer DaemonSet pod for growth and
correctness:

```bash
# Process/memory growth over the soak duration — should plateau, not climb unbounded
oc exec -n certsight <cert-analyzer-pod> -- curl -s http://localhost:9090/metrics \
  | grep -E 'cert_analyzer_process_(rss_bytes|cpu_percent)|cert_analyzer_cache_known_certs_size'

# Re-access cap holding (should stay bounded, not grow per-process * per-cert)
oc exec -n certsight <cert-analyzer-pod> -- curl -s http://localhost:9090/metrics \
  | grep -c '^tls_certificate_process_info'

# No cache-cap alert firing
oc exec -n certsight <cert-analyzer-pod> -- curl -s http://localhost:9090/metrics \
  | grep cert_analyzer_cache_known_certs_size
```

Each `soak_test.py` iteration also prints the exact `oc logs`/`curl` commands
to check that specific iteration's bundle and canary landed correctly.

## Clean up

```bash
oc delete job cert-soak-test -n certsight
oc delete rolebinding cert-soak-test-privileged-scc -n certsight
oc delete serviceaccount cert-soak-test -n certsight
```

`soak_test.py` deletes its own generated bundle/canary files after each
iteration (pass `--keep` to leave them for inspection).
