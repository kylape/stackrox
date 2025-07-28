#!/bin/bash

set -xeo pipefail

component="$1"
namespace="$2"

if [[ -z "$1" ]]; then
    echo "Usage: $0 [component] [namespace]"
    exit 0
fi

if [[ "$component" == "sensor" ]]; then
    binary=kubernetes
    app=sensor
    container=sensor
elif [[ "$component" == "central" ]]; then
    binary=central
    app=central
    container=central
elif [[ "$component" == "vsock-listener" ]]; then
    binary=vsock-listener
    app=collector
    container=vsock-listener
else
    echo Provide component: sensor, central, vsock-listener
    exit 1
fi

if [[ -z "$namespace" ]]; then
    echo "note: assuming default namespace"
    namespace="default"
fi

make bin/$binary
pod_name=$(kubectl -n "$namespace" get pod -l app=$app -oname)

hotload_cmd=$(cat << EOF
set -xeo pipefail
cat - > /tmp/$binary &&
chmod +x /tmp/$binary &&
mv /tmp/$binary /stackrox
pid=\$(pgrep $binary)
kill \$pid
sleep 5
[[ -d "/proc/\$pid" ]] && kill -9 \$pid
EOF
)

kubectl exec -n "$namespace" -i $pod_name -c $container -- sh -c "$hotload_cmd" < bin/$binary
