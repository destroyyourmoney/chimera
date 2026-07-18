package provision

import (
	"fmt"
	"strings"
)

func buildDeployScript(spec DeploySpec, shortIDs []string) (string, error) {
	sids := strings.Join(shortIDs, ",")
	fields := map[string]string{
		"repo":      spec.Repo,
		"ref":       spec.Ref,
		"image":     spec.Image,
		"container": spec.Container,
		"steal":     spec.StealHost,
		"sids":      sids,
	}
	for name, v := range fields {
		if strings.ContainsAny(v, "'\n") {
			return "", fmt.Errorf("provision: unsafe character in %s %q", name, v)
		}
	}

	q := func(s string) string { return "'" + s + "'" }

	type listenerPlan struct {
		transport     string
		port          int
		containerName string
	}
	plans := []listenerPlan{{transport: "", port: spec.ServerPort, containerName: spec.Container}}
	for _, l := range spec.ExtraListeners {
		plans = append(plans, listenerPlan{
			transport:     l.Transport,
			port:          l.Port,
			containerName: spec.Container + "-" + l.Transport,
		})
	}

	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("export DEBIAN_FRONTEND=noninteractive\n")

	for _, p := range plans {
		port := fmt.Sprintf("%d", p.port)
		b.WriteString("PORT_BUSY=0\n")
		b.WriteString("if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | awk '{print $4}' | grep -qE \":" + port + "$\"; then PORT_BUSY=1; fi\n")
		b.WriteString("if [ \"$PORT_BUSY\" = 1 ] && command -v docker >/dev/null 2>&1; then\n")
		b.WriteString("  STALE=$(docker ps -q --filter " + q("label="+chimeraLabel) + " --filter " + q("publish="+port) + " 2>/dev/null | head -n1)\n")
		b.WriteString("  if [ -n \"$STALE\" ]; then docker rm -f \"$STALE\" >/dev/null 2>&1 || true; PORT_BUSY=0; fi\n")
		b.WriteString("fi\n")
		b.WriteString("if [ \"$PORT_BUSY\" = 1 ]; then ")
		b.WriteString("echo \"" + portInUseMarker + ": port " + port + " is already in use on this server\" >&2; exit 1; fi\n")
	}

	b.WriteString("if ! command -v git >/dev/null 2>&1; then ")
	b.WriteString("(apt-get update && apt-get install -y --no-install-recommends git) >/dev/null 2>&1; fi\n")
	b.WriteString("if ! command -v docker >/dev/null 2>&1; then ")
	b.WriteString("curl -fsSL https://get.docker.com | sh >/dev/null 2>&1; fi\n")

	b.WriteString("DIR=" + q(remoteDir) + "\n")
	b.WriteString("if [ -d \"$DIR/.git\" ]; then ")
	b.WriteString("git -C \"$DIR\" fetch --depth 1 origin " + q(spec.Ref) + " && ")
	b.WriteString("git -C \"$DIR\" checkout -f FETCH_HEAD; ")
	b.WriteString("else rm -rf \"$DIR\" && git clone --depth 1 --branch " + q(spec.Ref) + " " + q(spec.Repo) + " \"$DIR\"; fi\n")

	b.WriteString("docker build -f \"$DIR/" + dockerfilePath + "\" --build-arg TAGS=" + q(serverBuildTags) +
		" -t " + q(spec.Image) + " \"$DIR\" >/dev/null\n")

	b.WriteString("KEYS=$(docker run --rm " + q(spec.Image) + " keygen)\n")
	b.WriteString("PRIV=$(printf '%s\\n' \"$KEYS\" | sed -n 's/^private[^:]*: *//p')\n")
	b.WriteString("PUB=$(printf '%s\\n' \"$KEYS\" | sed -n 's/^public[^:]*: *//p')\n")
	b.WriteString("if [ -z \"$PRIV\" ] || [ -z \"$PUB\" ]; then echo 'keygen failed' >&2; exit 1; fi\n")

	for _, p := range plans {
		port := fmt.Sprintf("%d", p.port)
		b.WriteString("docker rm -f " + q(p.containerName) + " >/dev/null 2>&1 || true\n")
		b.WriteString("docker run -d --name " + q(p.containerName) + " --label " + q(chimeraLabel) + " --restart unless-stopped ")
		b.WriteString("-p " + port + ":" + port + "/tcp -p " + port + ":" + port + "/udp ")
		b.WriteString(q(spec.Image) + " server -listen :" + port)
		if p.transport != "" {
			b.WriteString(" -transport " + q(p.transport))
		}
		b.WriteString(" -steal-host " + q(spec.StealHost) + " -priv \"$PRIV\" -sid " + q(sids) + "\n")
	}

	b.WriteString("echo \"" + pubMarker + "$PUB\"\n")
	return b.String(), nil
}
