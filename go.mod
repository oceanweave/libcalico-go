module github.com/projectcalico/libcalico-go

go 1.15

require (
	github.com/coreos/go-semver v0.3.0
	github.com/coreos/go-systemd v0.0.0-20190719114852-fd7a80b32e1f // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/go-playground/locales v0.12.1 // indirect
	github.com/go-playground/universal-translator v0.0.0-20170327191703-71201497bace // indirect
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.9.6 // indirect
	github.com/kelseyhightower/envconfig v0.0.0-20180517194557-dd1402a4d99d
	github.com/leodido/go-urn v0.0.0-20181204092800-a67a23e1c1af // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/projectcalico/go-json v0.0.0-20161128004156-6219dc7339ba // indirect
	github.com/projectcalico/go-yaml-wrapper v0.0.0-20191112210931-090425220c54
	github.com/prometheus/client_golang v1.0.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/tmc/grpc-websocket-proxy v0.0.0-20190109142713-0ad062ec5ee5 // indirect
	go.etcd.io/etcd v0.5.0-alpha.5.0.20200401174654-e694b7bb0875
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20200324154536-ceff61240acf
	google.golang.org/genproto v0.0.0-20191203220235-3fa9dbf08042 // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v9 v9.27.0
	gopkg.in/tchap/go-patricia.v2 v2.2.6
	gopkg.in/yaml.v2 v2.2.8 // indirect
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/client-go v0.17.2
	k8s.io/code-generator v0.17.2
	k8s.io/cri-api v0.17.2
	k8s.io/kubernetes v1.17.2

	// k8s.io/utils is not (tag) versioned
	k8s.io/utils v0.0.0-20191114200735-6ca3b61696b6 // indirect
)

replace k8s.io/api => k8s.io/api v0.17.2

replace k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.17.2

replace k8s.io/apimachinery => k8s.io/apimachinery v0.17.3-beta.0

replace k8s.io/apiserver => k8s.io/apiserver v0.17.2

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.17.2

replace k8s.io/client-go => k8s.io/client-go v0.17.2

replace k8s.io/cloud-provider => k8s.io/cloud-provider v0.17.2

replace k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.17.2

replace k8s.io/code-generator => k8s.io/code-generator v0.17.3-beta.0

replace k8s.io/component-base => k8s.io/component-base v0.17.2

replace k8s.io/cri-api => k8s.io/cri-api v0.17.3-beta.0

replace k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.17.2

replace k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.17.2

replace k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.17.2

replace k8s.io/kube-proxy => k8s.io/kube-proxy v0.17.2

replace k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.17.2

replace k8s.io/kubectl => k8s.io/kubectl v0.17.2

replace k8s.io/kubelet => k8s.io/kubelet v0.17.2

replace k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.17.2

replace k8s.io/metrics => k8s.io/metrics v0.17.2

replace k8s.io/node-api => k8s.io/node-api v0.17.2

replace k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.17.2

replace k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.17.2

replace k8s.io/sample-controller => k8s.io/sample-controller v0.17.2
