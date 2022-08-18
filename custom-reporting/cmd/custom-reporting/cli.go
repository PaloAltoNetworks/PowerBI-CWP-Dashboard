package custom_reporting

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

const version = "1.0.0"

func CreateCLI() (*cobra.Command, *options) {
	opts := options{}
	cmd := &cobra.Command{
		Use: "custom-reporting",
		Long: "Custom Developed Reporting tool for Delta Airlines created by " +
			"Palo Alto Networks Professional Services. Copyright Palo Alto Networks 2022",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.GenerateReports(); err != nil {
				return err
			}
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.validateInputs(); err != nil {
				return err
			}
			return nil
		},
		Example: "./custom-reporting -d -e -f /path/to/reports -p api.prismacloud.io --debug",
	}
	cmd.Version = version
	cmd.Flags().StringVarP(&opts.apiUrl, "prismaApiUrl", "p", "", "API URL for your Tenant: https://prisma.pan.dev/api/cloud/api-urls/")
	cmd.Flags().StringVarP(&opts.filePath, "filePath", "f", "", "Location where results will be written")
	cmd.Flags().BoolVarP(&opts.executiveSummary, "executiveReport", "e", false, "Generates the Executive Summary")
	cmd.Flags().BoolVarP(&opts.detailedReport, "detailedReport", "d", false, "Generates the Detailed Report")
	cmd.Flags().BoolVarP(&opts.sslVerify, "sslVerify", "", false,
		"If switch provided. The system's certificate pool will be used to validate Prisma Cloud's web certificate")
	cmd.Flags().BoolVarP(&opts.debug, "debug", "", false, "Enable Debug Logging")
	return cmd, &opts
}

func (o *options) validateInputs() error {

	if os.Getenv(accessKeyEnvVar) == "" {
		return &GenericError{Msg: fmt.Sprintf("OS ENV VARS %v is not populated", accessKeyEnvVar)}
	}
	if os.Getenv(secretKeyEnvVar) == "" {
		return &GenericError{Msg: fmt.Sprintf("OS ENV VARS %v is not populated", secretKeyEnvVar)}
	}
	if o.apiUrl == "" {
		return &GenericError{Msg: "API URL is not populated"}
	}
	if o.filePath == "" {
		return &GenericError{Msg: "File Path not populated"}
	}
	return nil
}

type options struct {
	apiUrl           string
	filePath         string
	executiveSummary bool
	detailedReport   bool
	sslVerify        bool
	debug            bool
}
