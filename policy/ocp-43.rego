package main

deny[msg] {
  input.apiVersion == "v1"
  input.kind == "Template"
  obj := input.objects[_]
  msg := _deny with input as obj
}

deny[msg] {
  input.apiVersion != "v1"
  input.kind != "Template"
  obj := input.objects[_]
  msg := _deny
}

warn[msg] {
  input.apiVersion == "v1"
  input.kind == "Template"
  obj := input.objects[_]
  msg := _warn with input as obj
}

warn[msg] {
  input.apiVersion != "v1"
  input.kind != "Template"
  obj := input.objects[_]
  msg := _warn
}

# imagestreams resources under v1 - use image.openshift.io/v1 instead
_deny = msg {
  input.apiVersion == "v1"
  input.kind == "ImageStream"
  msg := sprintf("%s/%s: API v1 for ImageStream is no longer served by default, use image.openshift.io/v1 instead.", [input.kind, input.metadata.name])
}

_deny = msg {
  input.apiVersion == "v1"
  input.kind == "Rolebinding"
  #input.roleRef.apiGroup == null
  msg := sprintf("%s/%s: RoleBinding roleRef.apiGroup key is null, use rbac.authorization.k8s.io instead.", [input.kind, input.metadata.name])
}
