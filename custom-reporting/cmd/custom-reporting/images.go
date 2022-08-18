package custom_reporting

import (
	"fmt"
	"github.com/go-gota/gota/dataframe"
	"github.com/sirupsen/logrus"
	"github.com/thathaneydude/prisma-cloud-sdk/cwpp"
	"github.com/thathaneydude/prisma-cloud-sdk/prisma"
	"golang.org/x/exp/slices"
	"strconv"
	"strings"
	"time"
)

var nonStandardSeverities = []string{"unimportant", "important", "negligible", "moderate"}

func fetchImagesPage(client *prisma.PrismaCloudClient, offset int, limit int) []cwpp.Image {
	logrus.Debugf("Fetching Images %v - %v", offset, offset+limit)
	query := cwpp.ImageQuery{
		Offset: strconv.Itoa(offset),
		Limit:  strconv.Itoa(limit),
	}
	images, err := client.Cwpp.ListImages(query)
	if err != nil {
		return nil
	}
	return images
}

func listAllImagesAndLoadDataframe(client *prisma.PrismaCloudClient) dataframe.DataFrame {
	var records []detailRecord
	offset := 0
	limit := 50
	for {
		page := fetchImagesPage(client, offset, limit)
		// if the page is empty, break out
		if page == nil {
			break
		}

		for _, image := range page {
			for _, vuln := range image.Vulnerabilities {
				if slices.Contains(nonStandardSeverities, vuln.Severity) {
					vuln.Severity = convertNonStandardSeverity(vuln.Cvss)
				}
				vulnAge := getVulnAge(vuln.Discovered)
				withinSLA, daysOver := isWithinSLA(vuln.Severity, vulnAge)
				records = append(records, detailRecord{
					Registry:                  image.RepoTag.Registry,
					Repository:                image.RepoTag.Repo,
					Tag:                       image.RepoTag.Tag,
					NumHostsAffected:          getNumHostsAffected(image),
					ImageCreationDate:         image.CreationTime.String(),
					FirstScanDate:             image.FirstScanTime.String(),
					LastScanDate:              image.ScanTime.String(),
					PackageNameAndVersion:     fmt.Sprintf("%v-%v", vuln.PackageName, vuln.PackageVersion),
					Status:                    vuln.Status,
					VulnerabilityAge:          vulnAge,
					DaysSinceFixMadeAvailable: getDaysSinceFixMadeAvailable(vuln.FixDate),
					Severity:                  vuln.Severity,
					CvssScore:                 fmt.Sprintf("%f", vuln.Cvss),
					Cve:                       vuln.Cve,
					CveLink:                   vuln.Link,
					OsDistributionAndVersion:  fmt.Sprintf("%v:%v", image.OsDistro, image.OsDistroVersion),
					Namespaces:                strings.Join(image.Namespaces, ","),
					Clusters:                  strings.Join(image.Clusters, ","),
					Labels:                    strings.Join(image.Labels, ","),
					ImageDigest:               image.Id,
					GoldenImage:               isGoldenImage(image.RepoTag.Registry),
					WithinSLA:                 withinSLA,
					DaysOverSLA:               daysOver,
				})
			}
		}

		// If it's the last page, break out of loop
		if len(page) < limit {
			break
		}
		offset += limit
	}
	return dataframe.LoadStructs(records)
}

func getNumHostsAffected(image cwpp.Image) int {
	var numHosts int
	for range image.Hosts {
		numHosts += 1
	}
	return numHosts
}

func getVulnAge(vulnDiscoveredDate time.Time) int {
	currentTime := time.Now()
	duration := currentTime.Sub(vulnDiscoveredDate)
	return int(duration.Hours() / 24)
}

func getDaysSinceFixMadeAvailable(fixDate int) int {
	currentTime := time.Now()
	duration := currentTime.Sub(time.Unix(int64(fixDate), 0))
	if fixDate == 0 {
		return 0
	}
	return int(duration.Hours() / 24)
}

func convertNonStandardSeverity(cvssScore float64) string {
	if cvssScore >= 9.0 && cvssScore <= 10.0 {
		return "critical"
	} else if cvssScore >= 7.0 && cvssScore <= 8.9 {
		return "high"
	} else if cvssScore >= 4.0 && cvssScore <= 6.9 {
		return "medium"
	} else {
		return "low"
	}
}

func isGoldenImage(imageRegistry string) bool {
	return strings.HasPrefix(strings.ToLower(imageRegistry), "nexus")
}

func isWithinSLA(severity string, vulnAgeDays int) (bool, int) {
	if severity == "critical" && vulnAgeDays > 30 {
		return false, vulnAgeDays - 30
	} else if severity == "high" && vulnAgeDays > 60 {
		return false, vulnAgeDays - 60
	} else if severity == "medium" && vulnAgeDays > 90 {
		return false, vulnAgeDays - 90
	} else if severity == "low" && vulnAgeDays > 120 {
		return false, vulnAgeDays - 120
	}
	return true, 0
}

type detailRecord struct {
	Registry                  string
	Repository                string
	Tag                       string
	NumHostsAffected          int
	ImageCreationDate         string
	FirstScanDate             string
	LastScanDate              string
	PackageNameAndVersion     string
	Status                    string
	VulnerabilityAge          int
	DaysSinceFixMadeAvailable int
	Severity                  string
	CvssScore                 string
	Cve                       string
	CveLink                   string
	OsDistributionAndVersion  string
	Namespaces                string
	Clusters                  string
	Labels                    string
	ImageDigest               string
	GoldenImage               bool
	WithinSLA                 bool
	DaysOverSLA               int
}
