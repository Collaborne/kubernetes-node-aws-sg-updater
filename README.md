# kubernetes-node-aws-sg-updater [![Build Status](https://travis-ci.org/Collaborne/kubernetes-node-aws-sg-updater.svg?branch=master)](https://travis-ci.org/Collaborne/kubernetes-node-aws-sg-updater)

Automatically keep AWS security groups up-to-date for nodes

This tool is deployed into a Kubernetes cluster, and will then monitor the nodes in the cluster, and synchronize rules for these nodes in a security group. This can be used in combination with EC2-classic to give a cluster (in a VPC) access to existing infrastructure.

# Example

Replace 'NAMESPACE' below with a suitable namespace.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: NAMESPACE
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: node-aws-sg-updater
  namespace: NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1alpha1
kind: ClusterRole
metadata:
  name: node-aws-sg-updater
rules:
- apiGroups:
  - ''
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: node-aws-sg-updater-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: node-aws-sg-updater
subjects:
- kind: ServiceAccount
  name: node-aws-sg-updater
  namespace: NAMESPACE
---
kind: Deployment
apiVersion: extensions/v1beta1
metadata:
  name: node-aws-sg-updater
  namespace: NAMESPACE
spec:
  replicas: 1
  template:
    metadata:
      labels:
        service: node-aws-sg-updater
    spec:
      serviceAccountName: node-aws-sg-updater
      containers:
      - name: node-aws-sg-updater
        image: 'collaborne/kubernetes-node-aws-sg-updater:latest'
        args: [
          "--security-group-id", "sg-XXXXXXXX",
          "--inbound-rule", "tcp:PORT",
          "--outbound-rule", "tcp:PORT"
        ]
        env:
        - name: AWS_REGION
          value: eu-west-1
```

You should assign a IAM role (using https://github.com/jtblin/kube2iam or https://github.com/uswitch/kiam) that has minimally these permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:DescribeSecurityGroups",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": [
                "arn:aws:ec2:REGION:ACCOUNT:security-group/sg-XXXXXXXX"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

## License

    MIT License

    Copyright (c) 2017 Collaborne

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
