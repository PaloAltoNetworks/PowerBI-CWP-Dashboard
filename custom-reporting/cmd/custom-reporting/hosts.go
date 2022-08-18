package custom_reporting

import (
	"github.com/sirupsen/logrus"
	"github.com/thathaneydude/prisma-cloud-sdk/cwpp"
	"github.com/thathaneydude/prisma-cloud-sdk/prisma"
	"strconv"
)

func fetchHostsPage(client *prisma.PrismaCloudClient, offset int, limit int) []cwpp.Host {
	logrus.Debugf("Fetching Hosts %v - %v", offset, offset+limit)
	query := cwpp.HostsQuery{
		Offset: strconv.Itoa(offset),
		Limit:  strconv.Itoa(limit),
	}
	hosts, err := client.Cwpp.ListHosts(query)
	if err != nil {
		return nil
	}
	return hosts
}

//func ListAllHostsAndLoadDataframe(client *prisma.PrismaCloudClient) dataframe.DataFrame {
//	return
//}
