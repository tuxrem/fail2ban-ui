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
	"path/filepath"
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
