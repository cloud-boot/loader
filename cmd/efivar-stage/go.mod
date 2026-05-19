module github.com/cloud-boot/loader/cmd/efivar-stage

go 1.25.0

require github.com/go-filesystems/uefi v0.0.0

require github.com/go-filesystems/interface v0.0.0 // indirect

// Until the mock repo is published on github.com, point at the local
// checkout. Same pattern as the rest of the cloud-boot repos.
replace github.com/go-filesystems/uefi => ../../../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/uefi

replace github.com/go-filesystems/interface => ../../../../../../../dev-temp/GitHub/mock/pkg/go-filesystems/interface
