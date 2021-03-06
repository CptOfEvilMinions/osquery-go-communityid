# Osquery-GO-CommunityID
<p align="center">
    <img src=".img/heart.png">
</p>

* [Creating my second Osquery extension with osquery-go](https://holdmybeersecurity.com/creating-my-second-osquery-extension-with-osquery-go)


## Local dev setup
1. Install golang
1. `mkdir -p $GOPATH/src/github.com/kolide/`
1. `go get github.com/kolide/osquery-go`
1. `go get github.com/Microsoft/go-winio`
1. `cd $GOPATH/src/github.com/kolide/osquery-go`
1. `make deps`

## Build executables
1. `GOOS=windows GOARCH=amd64 go build -o osquery_community_id_ext.exe osquery_community_id_ext.go`
    1. Compile exeutable for Windows
1. `GOOS=darwin GOARCH=amd64 go build -o osquery_community_id.ext osquery_community_id_ext.go`
    1. Compile exeutable for macOS


## References
* [osquery-go](https://github.com/kolide/osquery-go)
* [StackOverflow - Cross compile Go on OSX?](https://stackoverflow.com/questions/12168873/cross-compile-go-on-osx)
* [StackOverFlow - How to convert int (int64) into uint16 in golang?](https://stackoverflow.com/questions/36144675/how-to-convert-int-int64-into-uint16-in-golang/36145819)
* [Go maps in action](https://blog.golang.org/go-maps-in-action)
* [How to iterate over a Map using for loop in Go?](https://www.golangprograms.com/how-to-iterate-over-a-map-using-for-loop-in-go.html)
* [Github - CptOfEvilMinions/osquery-py-communityid](https://github.com/CptOfEvilMinions/osquery-py-communityid/blob/master/osquery_community_id.py)
* [How To Build Go Executables for Multiple Platforms on Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/how-to-build-go-executables-for-multiple-platforms-on-ubuntu-16-04)
* [Github - kolide/launcher - launcher-extension.go](https://github.com/kolide/launcher/blob/master/cmd/launcher.ext/launcher-extension.go)
* [Process and socket auditing with osquery](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/#osquery-events-optimization)
* [Extending Osquery with Go](https://blog.gopheracademy.com/advent-2017/osquery-sdk/)
* []()
* []()