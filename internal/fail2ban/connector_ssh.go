package fail2ban

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/swissmakers/fail2ban-ui/internal/config"
)

const sshEnsureActionScript = `sudo python3 - <<'PY'
import base64
import pathlib

action_dir = pathlib.Path("/etc/fail2ban/action.d")
action_dir.mkdir(parents=True, exist_ok=True)
action_cfg = base64.b64decode("__PAYLOAD__").decode("utf-8")
(action_dir / "ui-custom-action.conf").write_text(action_cfg)

jail_file = pathlib.Path("/etc/fail2ban/jail.local")
if not jail_file.exists():
    jail_file.write_text("[DEFAULT]\n")

lines = jail_file.read_text().splitlines()
already = any("Custom Fail2Ban action applied by fail2ban-ui" in line for line in lines)
if not already:
    new_lines = []
    inserted = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("action") and "ui-custom-action" not in stripped and not inserted:
            if not stripped.startswith("#"):
                new_lines.append("# " + line)
            else:
                new_lines.append(line)
            new_lines.append("# Custom Fail2Ban action applied by fail2ban-ui")
            new_lines.append("action = %(action_mwlg)s")
            inserted = True
            continue
        new_lines.append(line)
    if not inserted:
        insert_at = None
        for idx, value in enumerate(new_lines):
            if value.strip().startswith("[DEFAULT]"):
                insert_at = idx + 1
                break
        if insert_at is None:
            new_lines.append("[DEFAULT]")
            insert_at = len(new_lines)
        new_lines.insert(insert_at, "# Custom Fail2Ban action applied by fail2ban-ui")
        new_lines.insert(insert_at + 1, "action = %(action_mwlg)s")
    jail_file.write_text("\n".join(new_lines) + "\n")
PY`

// SSHConnector connects to a remote Fail2ban instance over SSH.
type SSHConnector struct {
	server config.Fail2banServer
}

// NewSSHConnector creates a new SSH connector.
func NewSSHConnector(server config.Fail2banServer) (Connector, error) {
	if server.Host == "" {
		return nil, fmt.Errorf("host is required for ssh connector")
	}
	if server.SSHUser == "" {
		return nil, fmt.Errorf("sshUser is required for ssh connector")
	}
	conn := &SSHConnector{server: server}
	if err := conn.ensureAction(context.Background()); err != nil {
		fmt.Printf("warning: failed to ensure remote fail2ban action for %s: %v\n", server.Name, err)
	}
	return conn, nil
}

func (sc *SSHConnector) ID() string {
	return sc.server.ID
}

func (sc *SSHConnector) Server() config.Fail2banServer {
	return sc.server
}

func (sc *SSHConnector) GetJailInfos(ctx context.Context) ([]JailInfo, error) {
	jails, err := sc.getJails(ctx)
	if err != nil {
		return nil, err
	}

	var infos []JailInfo
	for _, jail := range jails {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		ips, err := sc.GetBannedIPs(ctx, jail)
		if err != nil {
			continue
		}
		infos = append(infos, JailInfo{
			JailName:      jail,
			TotalBanned:   len(ips),
			NewInLastHour: 0,
			BannedIPs:     ips,
			Enabled:       true,
		})
	}

	sort.SliceStable(infos, func(i, j int) bool {
		return infos[i].JailName < infos[j].JailName
	})
	return infos, nil
}

func (sc *SSHConnector) GetBannedIPs(ctx context.Context, jail string) ([]string, error) {
	out, err := sc.runFail2banCommand(ctx, "status", jail)
	if err != nil {
		return nil, err
	}
	var bannedIPs []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				ips := strings.Fields(strings.TrimSpace(parts[1]))
				bannedIPs = append(bannedIPs, ips...)
			}
			break
		}
	}
	return bannedIPs, nil
}

func (sc *SSHConnector) UnbanIP(ctx context.Context, jail, ip string) error {
	_, err := sc.runFail2banCommand(ctx, "set", jail, "unbanip", ip)
	return err
}

func (sc *SSHConnector) Reload(ctx context.Context) error {
	_, err := sc.runFail2banCommand(ctx, "reload")
	return err
}

func (sc *SSHConnector) Restart(ctx context.Context) error {
	_, err := sc.runRemoteCommand(ctx, []string{"sudo", "systemctl", "restart", "fail2ban"})
	return err
}

func (sc *SSHConnector) GetFilterConfig(ctx context.Context, jail string) (string, error) {
	path := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", jail)
	out, err := sc.runRemoteCommand(ctx, []string{"sudo", "cat", path})
	if err != nil {
		return "", fmt.Errorf("failed to read remote filter config: %w", err)
	}
	return out, nil
}

func (sc *SSHConnector) SetFilterConfig(ctx context.Context, jail, content string) error {
	path := fmt.Sprintf("/etc/fail2ban/filter.d/%s.conf", jail)
	cmd := fmt.Sprintf("cat <<'EOF' | sudo tee %s >/dev/null\n%s\nEOF", path, content)
	_, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", cmd})
	return err
}

func (sc *SSHConnector) FetchBanEvents(ctx context.Context, limit int) ([]BanEvent, error) {
	// Not available over SSH without copying logs; return empty slice.
	return []BanEvent{}, nil
}

func (sc *SSHConnector) ensureAction(ctx context.Context) error {
	callbackURL := config.GetCallbackURL()
	actionConfig := config.BuildFail2banActionConfig(callbackURL)
	payload := base64.StdEncoding.EncodeToString([]byte(actionConfig))
	script := strings.ReplaceAll(sshEnsureActionScript, "__PAYLOAD__", payload)
	_, err := sc.runRemoteCommand(ctx, []string{"bash", "-lc", script})
	return err
}

func (sc *SSHConnector) getJails(ctx context.Context) ([]string, error) {
	out, err := sc.runFail2banCommand(ctx, "status")
	if err != nil {
		return nil, err
	}
	var jails []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Jail list:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				raw := strings.TrimSpace(parts[1])
				jails = strings.Split(raw, ",")
				for i := range jails {
					jails[i] = strings.TrimSpace(jails[i])
				}
			}
		}
	}
	return jails, nil
}

func (sc *SSHConnector) runFail2banCommand(ctx context.Context, args ...string) (string, error) {
	fail2banArgs := sc.buildFail2banArgs(args...)
	cmdArgs := append([]string{"sudo", "fail2ban-client"}, fail2banArgs...)
	return sc.runRemoteCommand(ctx, cmdArgs)
}

func (sc *SSHConnector) buildFail2banArgs(args ...string) []string {
	if sc.server.SocketPath == "" {
		return args
	}
	base := []string{"-s", sc.server.SocketPath}
	return append(base, args...)
}

func (sc *SSHConnector) runRemoteCommand(ctx context.Context, command []string) (string, error) {
	args := sc.buildSSHArgs(command)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	settingSnapshot := config.GetSettings()
	if settingSnapshot.Debug {
		config.DebugLog("SSH command [%s]: ssh %s", sc.server.Name, strings.Join(args, " "))
	}
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if settingSnapshot.Debug {
			config.DebugLog("SSH command error [%s]: %v | output: %s", sc.server.Name, err, output)
		}
		return output, fmt.Errorf("ssh command failed: %w (output: %s)", err, output)
	}
	if settingSnapshot.Debug {
		config.DebugLog("SSH command output [%s]: %s", sc.server.Name, output)
	}
	return output, nil
}

func (sc *SSHConnector) buildSSHArgs(command []string) []string {
	args := []string{"-o", "BatchMode=yes"}
	if sc.server.SSHKeyPath != "" {
		args = append(args, "-i", sc.server.SSHKeyPath)
	}
	if sc.server.Port > 0 {
		args = append(args, "-p", strconv.Itoa(sc.server.Port))
	}
	target := sc.server.Host
	if sc.server.SSHUser != "" {
		target = fmt.Sprintf("%s@%s", sc.server.SSHUser, target)
	}
	args = append(args, target)
	args = append(args, command...)
	return args
}
