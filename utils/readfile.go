package utils

import (
	"bufio"
	"os"
)

// ReadFileLinesToStringSlice takes a path as string, tries to open the file,
// reads its contents and returns the contents as string slice. Similar to
// Python's readlines()
func ReadFileLinesToStringSlice(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	res := make([]string, 0)
	for scanner.Scan() {
		res = append(res, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}
