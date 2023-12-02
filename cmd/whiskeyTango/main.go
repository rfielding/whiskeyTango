package main

import (
	"fmt"

	"github.com/rfielding/whiskeyTango/wt"
)

func main() {
	err := wt.Main()
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}
}
