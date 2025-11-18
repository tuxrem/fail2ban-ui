// Fail2ban UI - A Swiss made, management interface for Fail2ban.
//
// Copyright (C) 2025 Swissmakers GmbH (https://swissmakers.ch)
//
// Licensed under the GNU General Public License, Version 3 (GPL-3.0)
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.gnu.org/licenses/gpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// GetFilterConfig returns the filter configuration using the default connector.
func GetFilterConfig(jail string) (string, error) {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return "", err
	}
	return conn.GetFilterConfig(context.Background(), jail)
}

// SetFilterConfig writes the filter configuration using the default connector.
func SetFilterConfig(jail, newContent string) error {
	conn, err := GetManager().DefaultConnector()
	if err != nil {
		return err
	}
	return conn.SetFilterConfig(context.Background(), jail, newContent)
}

// GetFilterConfigLocal reads a filter configuration from the local filesystem.
func GetFilterConfigLocal(jail string) (string, error) {
	configPath := filepath.Join("/etc/fail2ban/filter.d", jail+".conf")
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config for jail %s: %v", jail, err)
	}
	return string(content), nil
}

// SetFilterConfigLocal writes the filter configuration to the local filesystem.
func SetFilterConfigLocal(jail, newContent string) error {
	configPath := filepath.Join("/etc/fail2ban/filter.d", jail+".conf")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config for jail %s: %v", jail, err)
	}
	return nil
}

// GetFiltersLocal returns a list of filter names from /etc/fail2ban/filter.d
func GetFiltersLocal() ([]string, error) {
	dir := "/etc/fail2ban/filter.d"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read filter directory: %w", err)
	}
	var filters []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			name := strings.TrimSuffix(entry.Name(), ".conf")
			filters = append(filters, name)
		}
	}
	sort.Strings(filters)
	return filters, nil
}

func normalizeLogLines(logLines []string) []string {
	var cleaned []string
	for _, line := range logLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cleaned = append(cleaned, line)
	}
	return cleaned
}

// TestFilterLocal tests a filter against log lines using fail2ban-regex
// Returns the full output of fail2ban-regex command
func TestFilterLocal(filterName string, logLines []string) (string, error) {
	cleaned := normalizeLogLines(logLines)
	if len(cleaned) == 0 {
		return "No log lines provided.\n", nil
	}
	filterPath := filepath.Join("/etc/fail2ban/filter.d", filterName+".conf")
	if _, err := os.Stat(filterPath); err != nil {
		return "", fmt.Errorf("filter %s not found: %w", filterName, err)
	}

	// Create a temporary log file with all log lines
	tmpFile, err := os.CreateTemp("", "fail2ban-test-*.log")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary log file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write all log lines to the temp file
	for _, logLine := range cleaned {
		if _, err := tmpFile.WriteString(logLine + "\n"); err != nil {
			return "", fmt.Errorf("failed to write to temporary log file: %w", err)
		}
	}
	tmpFile.Close()

	// Run fail2ban-regex with the log file and filter config
	// Format: fail2ban-regex /path/to/logfile /etc/fail2ban/filter.d/filter-name.conf
	cmd := exec.Command("fail2ban-regex", tmpFile.Name(), filterPath)
	out, _ := cmd.CombinedOutput()
	output := string(out)

	// Return the full output regardless of exit code (fail2ban-regex may exit non-zero for no matches)
	// The output contains useful information even when there are no matches
	return output, nil
}
