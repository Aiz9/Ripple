// apktriage runs the offline APK inspector without PostgreSQL or an LLM.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Aiz9/ripple/internal/androidapk"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: apktriage path/to/application.apk")
		os.Exit(2)
	}
	report, err := androidapk.Analyze(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
