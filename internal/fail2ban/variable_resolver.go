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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

var (
	// Variable pattern: %(variable_name)s
	variablePattern = regexp.MustCompile(`%\(([^)]+)\)s`)
)

// extractVariablesFromString extracts all variable names from a string.
// Returns a list of variable names found in the pattern %(name)s.
func extractVariablesFromString(s string) []string {
	matches := variablePattern.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}

	var variables []string
	for _, match := range matches {
		if len(match) > 1 {
			variables = append(variables, match[1])
		}
	}
	return variables
}

// searchVariableInFile searches for a variable definition in a single file.
// Returns the value if found, empty string if not found, and error on file read error.
func searchVariableInFile(filePath, varName string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentVar string
	var currentValue strings.Builder
	var inMultiLine bool
	var pendingLine string
	var pendingLineOriginal string

	for {
		var originalLine string
		var line string

		if pendingLine != "" {
			originalLine = pendingLineOriginal
			line = pendingLine
			pendingLine = ""
			pendingLineOriginal = ""
		} else {
			if !scanner.Scan() {
				break
			}
			originalLine = scanner.Text()
			line = strings.TrimSpace(originalLine)
		}

		if !inMultiLine && (strings.HasPrefix(line, "#") || line == "") {
			continue
		}

		if !inMultiLine {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				if strings.EqualFold(key, varName) {
					config.DebugLog("findVariableDefinition: found variable '%s' = '%s' in file %s", key, value, filePath)
					currentVar = key
					currentValue.WriteString(value)

					if scanner.Scan() {
						nextLineOriginal := scanner.Text()
						nextLineTrimmed := strings.TrimSpace(nextLineOriginal)

						isContinuation := nextLineTrimmed != "" &&
							!strings.HasPrefix(nextLineTrimmed, "#") &&
							!strings.HasPrefix(nextLineTrimmed, "[") &&
							(strings.HasPrefix(nextLineOriginal, " ") || strings.HasPrefix(nextLineOriginal, "\t") ||
								(!strings.Contains(nextLineTrimmed, "=")))

						if isContinuation {
							inMultiLine = true
							pendingLine = nextLineTrimmed
							pendingLineOriginal = nextLineOriginal
							continue
						} else {
							return strings.TrimSpace(currentValue.String()), nil
						}
					} else {
						return strings.TrimSpace(currentValue.String()), nil
					}
				}
			}
		} else {
			trimmedLine := strings.TrimSpace(originalLine)

			if strings.HasPrefix(trimmedLine, "[") {
				return strings.TrimSpace(currentValue.String()), nil
			}

			if strings.Contains(trimmedLine, "=") && !strings.HasPrefix(originalLine, " ") && !strings.HasPrefix(originalLine, "\t") {
				return strings.TrimSpace(currentValue.String()), nil
			}

			if currentValue.Len() > 0 {
				currentValue.WriteString(" ")
			}
			currentValue.WriteString(trimmedLine)

			if scanner.Scan() {
				nextLineOriginal := scanner.Text()
				nextLineTrimmed := strings.TrimSpace(nextLineOriginal)

				if nextLineTrimmed == "" ||
					strings.HasPrefix(nextLineTrimmed, "#") ||
					strings.HasPrefix(nextLineTrimmed, "[") ||
					(strings.Contains(nextLineTrimmed, "=") && !strings.HasPrefix(nextLineOriginal, " ") && !strings.HasPrefix(nextLineOriginal, "\t")) {
					return strings.TrimSpace(currentValue.String()), nil
				}
				pendingLine = nextLineTrimmed
				pendingLineOriginal = nextLineOriginal
				continue
			} else {
				return strings.TrimSpace(currentValue.String()), nil
			}
		}
	}

	if inMultiLine && currentVar != "" {
		return strings.TrimSpace(currentValue.String()), nil
	}

	return "", nil
}

// findVariableDefinition searches for a variable definition in all .local files first,
// then .conf files under /etc/fail2ban/ and subdirectories.
// Returns the FIRST value found (prioritizing .local over .conf).
func findVariableDefinition(varName string) (string, error) {
	fail2banPath := "/etc/fail2ban"

	config.DebugLog("findVariableDefinition: searching for variable '%s'", varName)

	if _, err := os.Stat(fail2banPath); os.IsNotExist(err) {
		return "", fmt.Errorf("variable '%s' not found: /etc/fail2ban directory does not exist", varName)
	}

	// First pass: search .local files (higher priority)
	var foundValue string
	err := filepath.Walk(fail2banPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".local") {
			return nil
		}

		value, err := searchVariableInFile(path, varName)
		if err != nil {
			return nil // Skip files we can't read
		}

		if value != "" {
			foundValue = value
			return filepath.SkipAll // Stop walking when found
		}

		return nil
	})

	if foundValue != "" {
		config.DebugLog("findVariableDefinition: returning value '%s' for variable '%s' (from .local file)", foundValue, varName)
		return foundValue, nil
	}

	if err != nil && err != filepath.SkipAll {
		return "", err
	}

	// Second pass: search .conf files (only if not found in .local)
	config.DebugLog("findVariableDefinition: variable '%s' not found in .local files, searching .conf files", varName)
	err = filepath.Walk(fail2banPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".conf") {
			return nil
		}

		value, err := searchVariableInFile(path, varName)
		if err != nil {
			return nil
		}

		if value != "" {
			foundValue = value
			return filepath.SkipAll // Stop walking when found
		}

		return nil
	})

	if foundValue != "" {
		config.DebugLog("findVariableDefinition: returning value '%s' for variable '%s' (from .conf file)", foundValue, varName)
		return foundValue, nil
	}

	if err != nil && err != filepath.SkipAll {
		return "", err
	}

	config.DebugLog("findVariableDefinition: variable '%s' not found", varName)
	return "", fmt.Errorf("variable '%s' not found in Fail2Ban configuration files", varName)
}

// resolveVariableRecursive resolves a variable recursively, handling nested variables.
// visited map tracks visited variables to detect circular references.
// This function fully resolves all nested variables until no variables remain.
func resolveVariableRecursive(varName string, visited map[string]bool) (string, error) {
	if visited[varName] {
		return "", fmt.Errorf("circular reference detected for variable '%s'", varName)
	}

	visited[varName] = true
	defer delete(visited, varName)

	value, err := findVariableDefinition(varName)
	if err != nil {
		return "", err
	}

	// Keep resolving until no more variables are found
	resolved := value
	maxIterations := 10
	iteration := 0

	for iteration < maxIterations {
		variables := extractVariablesFromString(resolved)
		if len(variables) == 0 {
			// No more variables, fully resolved
			config.DebugLog("resolveVariableRecursive: '%s' fully resolved to '%s'", varName, resolved)
			break
		}

		config.DebugLog("resolveVariableRecursive: iteration %d for '%s', found %d variables in '%s': %v", iteration+1, varName, len(variables), resolved, variables)

		// Resolve all nested variables
		for _, nestedVar := range variables {
			// Check for circular reference
			if visited[nestedVar] {
				return "", fmt.Errorf("circular reference detected: '%s' -> '%s'", varName, nestedVar)
			}

			config.DebugLog("resolveVariableRecursive: resolving nested variable '%s' for '%s'", nestedVar, varName)
			nestedValue, err := resolveVariableRecursive(nestedVar, visited)
			if err != nil {
				return "", fmt.Errorf("failed to resolve variable '%s' in '%s': %w", nestedVar, varName, err)
			}

			config.DebugLog("resolveVariableRecursive: resolved '%s' to '%s' for '%s'", nestedVar, nestedValue, varName)

			// Replace ALL occurrences of the nested variable
			// Pattern: %(varName)s - need to escape parentheses for regex
			// The pattern %(varName)s needs to be escaped as %\(varName\)s in regex
			pattern := fmt.Sprintf("%%\\(%s\\)s", regexp.QuoteMeta(nestedVar))
			re := regexp.MustCompile(pattern)
			beforeReplace := resolved
			resolved = re.ReplaceAllString(resolved, nestedValue)
			config.DebugLog("resolveVariableRecursive: replaced pattern '%s' in '%s' with '%s', result: '%s'", pattern, beforeReplace, nestedValue, resolved)

			// Verify the replacement actually happened
			if beforeReplace == resolved {
				config.DebugLog("resolveVariableRecursive: WARNING - replacement did not change string! Pattern: '%s', Before: '%s', After: '%s'", pattern, beforeReplace, resolved)
				// If replacement didn't work, this is a critical error
				return "", fmt.Errorf("failed to replace variable '%s' in '%s': pattern '%s' did not match", nestedVar, beforeReplace, pattern)
			}
		}

		// After replacing all variables in this iteration, check if we're done
		// Verify no variables remain before continuing
		remainingVars := extractVariablesFromString(resolved)
		if len(remainingVars) == 0 {
			// No more variables, fully resolved
			config.DebugLog("resolveVariableRecursive: '%s' fully resolved to '%s' after replacements", varName, resolved)
			break
		}

		// If we still have variables after replacement, continue to next iteration
		// But check if we made progress (resolved should be different from before)
		iteration++
	}

	if iteration >= maxIterations {
		return "", fmt.Errorf("maximum resolution iterations reached for variable '%s', possible circular reference. Last resolved value: '%s'", varName, resolved)
	}

	return resolved, nil
}

// ResolveLogpathVariables resolves all variables in a logpath string.
// Returns the fully resolved path. If no variables are present, returns the original path.
// Keeps resolving until no more variables are found (handles nested variables).
func ResolveLogpathVariables(logpath string) (string, error) {
	if logpath == "" {
		return "", nil
	}

	logpath = strings.TrimSpace(logpath)

	// Keep resolving until no more variables are found
	resolved := logpath
	maxIterations := 10 // Prevent infinite loops
	iteration := 0

	for iteration < maxIterations {
		variables := extractVariablesFromString(resolved)
		if len(variables) == 0 {
			// No more variables, we're done
			break
		}

		config.DebugLog("ResolveLogpathVariables: iteration %d, found %d variables in '%s'", iteration+1, len(variables), resolved)

		// Resolve all variables found in the current string
		visited := make(map[string]bool)
		for _, varName := range variables {
			config.DebugLog("ResolveLogpathVariables: resolving variable '%s' from string '%s'", varName, resolved)
			varValue, err := resolveVariableRecursive(varName, visited)
			if err != nil {
				return "", fmt.Errorf("failed to resolve variable '%s': %w", varName, err)
			}

			config.DebugLog("ResolveLogpathVariables: resolved variable '%s' to '%s'", varName, varValue)

			// Replace ALL occurrences of the variable in the resolved string
			// Pattern: %(varName)s - need to escape parentheses for regex
			// The pattern %(varName)s needs to be escaped as %\(varName\)s in regex
			pattern := fmt.Sprintf("%%\\(%s\\)s", regexp.QuoteMeta(varName))
			re := regexp.MustCompile(pattern)
			beforeReplace := resolved
			resolved = re.ReplaceAllString(resolved, varValue)
			config.DebugLog("ResolveLogpathVariables: replaced pattern '%s' in '%s' with '%s', result: '%s'", pattern, beforeReplace, varValue, resolved)
		}

		iteration++
	}

	if iteration >= maxIterations {
		return "", fmt.Errorf("maximum resolution iterations reached, possible circular reference in logpath '%s'", logpath)
	}

	config.DebugLog("Resolved logpath: '%s' -> '%s'", logpath, resolved)
	return resolved, nil
}
