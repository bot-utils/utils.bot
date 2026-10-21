// Private operator capability test. It never accepts a customer URL or payment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	vm "github.com/aws/aws-sdk-go-v2/service/lambdamicrovms"
	"github.com/aws/aws-sdk-go-v2/service/lambdamicrovms/types"
	"github.com/aws/smithy-go"
	"pdfservice/internal/awsenv"
	"pdfservice/internal/jsonwire"
	"pdfservice/internal/microvm"
)

func fail(err error) {
	code := "operation_unavailable"
	var failure *microvm.Failure
	if errors.As(err, &failure) {
		code = failure.Error()
	}
	var service smithy.APIError
	if errors.As(err, &service) {
		code = service.ErrorCode()
	}
	fmt.Fprintln(os.Stderr, code)
	os.Exit(1)
}
func main() {
	cleanup := flag.Bool("check-cleanup", false, "verify no active MicroVMs for the configured image; read only")
	imageState := flag.Bool("image-state", false, "inspect configured image state; read only")
	discover := flag.Bool("discover", false, "list managed base image versions; read only")
	flag.Parse()
	cfg, err := awsenv.Load()
	if err != nil {
		fail(err)
	}
	client := vm.NewFromConfig(cfg, func(o *vm.Options) { o.RetryMaxAttempts = 2 })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if *imageState {
		image := os.Getenv("MICROVM_IMAGE_ARN")
		if image == "" {
			fail(microvm.ErrUnavailable)
		}
		out, err := client.GetMicrovmImage(ctx, &vm.GetMicrovmImageInput{ImageIdentifier: aws.String(image)})
		if err != nil {
			fail(err)
		}
		fmt.Println(out.State)
		versions, err := client.ListMicrovmImageVersions(ctx, &vm.ListMicrovmImageVersionsInput{ImageIdentifier: aws.String(image), MaxResults: aws.Int32(50)})
		if err != nil {
			fail(err)
		}
		for _, version := range versions.Items {
			fmt.Println(aws.ToString(version.ImageVersion), version.State, version.Status, aws.ToString(version.StateReason))
		}
		return
	}
	if *discover {
		out, e := client.ListManagedMicrovmImageVersions(ctx, &vm.ListManagedMicrovmImageVersionsInput{ImageIdentifier: aws.String("arn:aws:lambda:us-east-2:aws:microvm-image:al2023-1"), MaxResults: aws.Int32(50)})
		if e != nil {
			fail(e)
		}
		for _, v := range out.Items {
			if v.Status == types.ManagedMicrovmImageVersionStatusAvailable {
				fmt.Println(aws.ToString(v.ImageVersion))
			}
		}
		return
	}
	if *cleanup {
		image := os.Getenv("MICROVM_IMAGE_ARN")
		if image == "" {
			fail(microvm.ErrUnavailable)
		}
		input := &vm.ListMicrovmsInput{ImageIdentifier: aws.String(image), MaxResults: aws.Int32(50)}
		states := map[string]int{}
		active := 0
		for {
			out, e := client.ListMicrovms(ctx, input)
			if e != nil {
				fail(e)
			}
			for _, job := range out.Items {
				states[string(job.State)]++
				if job.State != types.MicrovmStateTerminated {
					active++
				}
			}
			if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
				break
			}
			input.NextToken = out.NextToken
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"states": states, "active": active})
		if active != 0 {
			os.Exit(1)
		}
		return
	}
	runner := microvm.Runner{API: client, Image: os.Getenv("MICROVM_IMAGE_ARN"), Version: os.Getenv("MICROVM_IMAGE_VERSION")}
	started := time.Now()
	wire, e := runner.Run(ctx, []byte(`{}`))
	if e != nil {
		fail(e)
	}
	var out struct {
		OK      bool  `json:"ok"`
		Elapsed int64 `json:"elapsedMS"`
	}
	if jsonwire.Decode(wire, &out, 1024) != nil || !out.OK {
		fail(microvm.ErrUnavailable)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": out.OK, "renderCheckMS": out.Elapsed, "totalIncludingTerminationMS": time.Since(started).Milliseconds()})
}
