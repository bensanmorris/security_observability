# Included in the test console and fleet manager server blocks.
sub_filter '</body>' '<script src="/k8s-demo/panel.js" defer></script></body>';
sub_filter_once on;

location = /k8s-demo/start {
    limit_req zone=k8s_demo_start burst=2 nodelay;
    proxy_pass http://127.0.0.1:8096;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /k8s-demo/ {
    limit_req zone=k8s_demo_general burst=20 nodelay;
    proxy_pass http://127.0.0.1:8096;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
