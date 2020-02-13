package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
	"github.com/satta/gommunityid"
)

// main input: Takes in user input where the Osquery socket is located
// This function registers this Osquery extension using the user provided socket path
// main output: None
func main() {
	if len(os.Args) != 2 {
		log.Fatalf(`Usage: %s SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("community_id", os.Args[1])
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("community_id", CommunityIDColumns(), CommunityIDTableGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// CommunityIDColumns input: None
// CommunityIDColumns output: Return the columns of the table and the variable type of each column.
func CommunityIDColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("src_ip"),
		table.IntegerColumn("src_port"),
		table.TextColumn("dst_ip"),
		table.IntegerColumn("dst_port"),
		table.IntegerColumn("protocol"),
		table.TextColumn("community_id"),
	}
}

// CommunityIDTableGenerate input: ctx and query context
// CommunityIDTableGenerate output: Returns a map which contains all the values passed into
// the table and the calculated communityID hash of for the network question
func CommunityIDTableGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	srcIP := queryContext.Constraints["src_ip"].Constraints[0].Expression
	srcPort, err := strconv.ParseUint(queryContext.Constraints["src_port"].Constraints[0].Expression, 10, 16)
	dstIP := queryContext.Constraints["dst_ip"].Constraints[0].Expression
	dstPort, err := strconv.ParseUint(queryContext.Constraints["dst_port"].Constraints[0].Expression, 10, 16)
	protocol, err := strconv.ParseUint(queryContext.Constraints["protocol"].Constraints[0].Expression, 10, 8)

	// If a translation failed return nil
	if err != nil {
		return nil, nil
	}

	// Generate community ID
	communityID := GenerateCommunityID(srcIP, uint16(srcPort), dstIP, uint16(dstPort), uint8(protocol))

	fmt.Println("%v\n%v\n%v\n%v\n%v\n", srcIP, srcPort, dstIP, dstPort, protocol)

	// Return data to render Osquery results table
	return []map[string]string{
		{
			"src_ip":       srcIP,
			"src_port":     strconv.FormatUint(srcPort, 10),
			"dst_ip":       dstIP,
			"dst_port":     strconv.FormatUint(dstPort, 10),
			"protocol":     strconv.FormatUint(protocol, 10),
			"community_id": communityID,
		},
	}, nil
}

// GenerateCommunityID input: srcIP, srcPort, dstIP, dstPort, protocol
// GenerateCommunityID output: communityID has of the network connection
func GenerateCommunityID(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol uint8) string {
	// Convert IP address strings to net format
	srcIPNet := net.ParseIP(srcIP)
	dstIPNet := net.ParseIP(dstIP)

	// Get instance for version 1, seed 0
	cid, _ := gommunityid.GetCommunityIDByVersion(1, 0)

	// Obtain flow tuple. This can be done any way you like.
	ft := gommunityid.MakeFlowTuple(srcIPNet, dstIPNet, srcPort, dstPort, protocol)

	// Calculate Base64-encoded value
	communityid := cid.CalcBase64(ft)

	return communityid
}
