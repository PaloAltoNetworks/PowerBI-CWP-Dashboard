package custom_reporting

import (
	"fmt"
	"github.com/go-gota/gota/dataframe"
	"github.com/go-gota/gota/series"
	"github.com/sirupsen/logrus"
	"github.com/thathaneydude/prisma-cloud-sdk/prisma"
	"os"
	"path"
	"strings"
)

const (
	accessKeyEnvVar = "PRISMA_ACCESS_KEY"
	secretKeyEnvVar = "PRISMA_SECRET_KEY"
	detailsFileName = "details.csv"
	summaryFileName = "summary.csv"
)

func (o *options) GenerateReports() error {
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	})
	if o.debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.Infof("Generating Reports")

	client, err := prisma.NewPrismaCloudClient(&prisma.Options{
		ApiUrl:    o.apiUrl,
		Username:  os.Getenv(accessKeyEnvVar),
		Password:  os.Getenv(secretKeyEnvVar),
		SslVerify: o.sslVerify,
	})

	if err != nil {
		return err
	}
	vulnRecords := listAllImagesAndLoadDataframe(client)

	if o.detailedReport {
		err = writeDetailedReport(vulnRecords, o.filePath)
		if err != nil {
			return nil
		}
	}

	if o.executiveSummary {
		err = writeSummaryReport(vulnRecords, o.filePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeSummaryReport(vulns dataframe.DataFrame, filePath string) error {
	const thirtyDaysSuffix = ">30 Days Old"
	const thirtyDaysWithHostsSuffix = ">30 Days Old With Hosts"
	summary := make(map[string]interface{})
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		summaryKey := fmt.Sprintf("%v %v", strings.Title(sev), thirtyDaysSuffix)
		summary[summaryKey] = vulns.FilterAggregation(
			dataframe.And,
			dataframe.F{Colname: "VulnerabilityAge", Comparator: series.GreaterEq, Comparando: 30},
			dataframe.F{Colname: "Severity", Comparator: series.Eq, Comparando: sev},
		).Nrow()
		logrus.Debugf("%v %v %v", summary[summaryKey], sev, thirtyDaysSuffix)
		summaryKey = fmt.Sprintf("%v %v", strings.Title(sev), thirtyDaysWithHostsSuffix)
		summary[summaryKey] = vulns.FilterAggregation(
			dataframe.And,
			dataframe.F{Colname: "VulnerabilityAge", Comparator: series.GreaterEq, Comparando: 30},
			dataframe.F{Colname: "Severity", Comparator: series.Eq, Comparando: sev},
			dataframe.F{Colname: "NumHostsAffected", Comparator: series.Greater, Comparando: 0},
		).Nrow()
		logrus.Debugf("%v %v %v", summary[summaryKey], sev, thirtyDaysWithHostsSuffix)
	}

	vulnStats := vulns.Describe().Col("VulnerabilityAge")
	summary["Minimum Vulnerability Age"] = vulnStats.Elem(3)
	summary["Maximum Vulnerability Age"] = vulnStats.Elem(7)
	summary["Median Vulnerability Age"] = vulnStats.Elem(1)
	summary["Mean Vulnerability Age"] = vulnStats.Elem(0)
	logrus.Debugf("%v", summary)

	df := dataframe.LoadMaps(
		[]map[string]interface{}{
			summary,
		},
	)
	fullPath := path.Join(filePath, summaryFileName)
	csvFile, _ := os.Create(fullPath)
	defer csvFile.Close()

	logrus.Infof("Writing summary report to %v", fullPath)
	err := df.WriteCSV(csvFile)
	if err != nil {
		return err
	}
	return nil
}

func writeDetailedReport(df dataframe.DataFrame, filePath string) error {
	fullPath := path.Join(filePath, detailsFileName)
	csvFile, err := os.Create(fullPath)
	defer csvFile.Close()

	logrus.Infof("Writing details report to %v", fullPath)
	err = df.WriteCSV(csvFile)
	if err != nil {
		return err
	}
	return nil
}
