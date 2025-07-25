package initbundles

import (
	"context"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/pkg/protocompat"
	pkgCommon "github.com/stackrox/rox/pkg/roxctl/common"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/rox/roxctl/common"
	"github.com/stackrox/rox/roxctl/common/environment"
	"github.com/stackrox/rox/roxctl/common/flags"
	"github.com/stackrox/rox/roxctl/common/util"
)

func listInitBundles(cliEnvironment environment.Environment, timeout time.Duration, retryTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(pkgCommon.Context(), timeout)
	defer cancel()

	conn, err := cliEnvironment.GRPCConnection(common.WithRetryTimeout(retryTimeout))
	if err != nil {
		return errors.Wrap(err, "establishing GRPC connection to list init bundles")
	}
	defer utils.IgnoreError(conn.Close)
	svc := v1.NewClusterInitServiceClient(conn)

	rsp, err := svc.GetInitBundles(ctx, &v1.Empty{})
	if err != nil {
		return errors.Wrap(err, "getting all init bundles")
	}

	bundles := rsp.GetItems()
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].GetName() < bundles[j].GetName() })

	return outputBundles(cliEnvironment.InputOutput().Out(), bundles)
}

func outputBundles(w io.Writer, bundles []*v1.InitBundleMeta) error {
	tabWriter := tabwriter.NewWriter(w, 4, 8, 2, '\t', 0)

	fmt.Fprintln(tabWriter, "Name\tCreated at\tExpires at\tCreated By\tID")
	fmt.Fprintln(tabWriter, "====\t==========\t==========\t==========\t==")

	for _, meta := range bundles {
		name := meta.GetName()
		if name == "" {
			name = "(empty)"
		}
		fmt.Fprintf(tabWriter, "%s\t%s\t%v\t%s\t%v\n",
			name,
			protocompat.ConvertTimestampToString(meta.GetCreatedAt(), time.RFC3339Nano),
			protocompat.ConvertTimestampToString(meta.GetExpiresAt(), time.RFC3339Nano),
			getPrettyUser(meta.GetCreatedBy()),
			meta.GetId(),
		)
	}

	return errors.Wrap(tabWriter.Flush(), "flushing tabular output")
}

// listCommand implements the command for listing init bundles.
func listCommand(cliEnvironment environment.Environment) *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List cluster init bundles",
		Long:  "List all previously generated init bundles for bootstrapping new StackRox secured clusters.",
		RunE: util.RunENoArgs(func(c *cobra.Command) error {
			return listInitBundles(cliEnvironment, flags.Timeout(c), flags.RetryTimeout(c))
		}),
	}
	return c
}
