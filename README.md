# Osquery-GO-CommunityID

This project provides a table in Osquery to calculate the communityID of a network connection.

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
1. `GOOS=darwin GOARCH=amd64 go build -o osquery_community_id_ext.macho osquery_community_id_ext.go`
    1. Compile exeutable for macOS


## References
* [osquery-go](https://github.com/kolide/osquery-go)
* [StackOverflow - Cross compile Go on OSX?](https://stackoverflow.com/questions/12168873/cross-compile-go-on-osx)
* [StackOverFlow - How to convert int (int64) into uint16 in golang?](https://stackoverflow.com/questions/36144675/how-to-convert-int-int64-into-uint16-in-golang/36145819)
* [Go maps in action](https://blog.golang.org/go-maps-in-action)
* [How to iterate over a Map using for loop in Go?](https://www.golangprograms.com/how-to-iterate-over-a-map-using-for-loop-in-go.html)
* [Github - CptOfEvilMinions/osquery-py-communityid](https://github.com/CptOfEvilMinions/osquery-py-communityid/blob/master/osquery_community_id.py)
* [How To Build Go Executables for Multiple Platforms on Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/how-to-build-go-executables-for-multiple-platforms-on-ubuntu-16-04)
* []()
* []()
* []()