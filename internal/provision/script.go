package provision

import (
	"fmt"
	"strings"
)

// buildDeployScript renders the idempotent remote provisioning script. Every
// operator-supplied value is single-quoted; values containing a single quote are
// rejected outright (no escaping games) so the script cannot be broken out of.
// The script keeps the freshly generated PRIVATE key in a shell variable on the
// VPS and prints only the public key back over the (encrypted) SSH channel.
//
// Multi-transport support (ROADMAP2 §3/§4): besides the primary Reality/TCP
// listener on spec.ServerPort, spec.ExtraListeners launches one additional
// `chimera server -transport X` container per entry, each in its own
// container (so they can be individually restarted/torn down) but all
// sharing the one keypair generated in step 4 -- one server identity across
// every transport it offers, matching internal/controlplane's catalog model
// (one CatalogServer, many CatalogListener rows, one pubkey).
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

	// listenerPlan is one docker container this script will (re)launch:
	// the primary Reality/TCP listener first, then one per ExtraListeners,
	// in order.
	type listenerPlan struct {
		transport     string // "" for the primary (no -transport flag: binary default), else "quic"|"ss"|"dot"
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

	// 0. Fail fast if any requested port is already bound by something else
	// (another web server, a leftover container under a different name,
	// etc.) -- otherwise the operator waits through the full apt/git/docker
	// build only to have a later `docker run -p` fail with a much less
	// legible daemon error. ss ships with iproute2, which is present on
	// every stock Ubuntu/Debian image; skip the check silently if it isn't
	// (the docker run step below still catches it, just later).
	//
	// If a port turns out to be held by a container THIS deploy tooling
	// created before (identified by the chimeraLabel below, not by name --
	// spec.Container may have been customized across deploys), remove that
	// stale container and continue rather than failing: a redeploy to a host
	// whose previous CHIMERA container is still bound to the port is the
	// common case (e.g. after this same port-check bug used to reject it
	// outright), not a real conflict. A port held by anything else -- an
	// unrelated service, or a container without our label -- still fails
	// with the clear error below instead of being clobbered.
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

	// 1. Ensure git + docker are present.
	b.WriteString("if ! command -v git >/dev/null 2>&1; then ")
	b.WriteString("(apt-get update && apt-get install -y --no-install-recommends git) >/dev/null 2>&1; fi\n")
	b.WriteString("if ! command -v docker >/dev/null 2>&1; then ")
	b.WriteString("curl -fsSL https://get.docker.com | sh >/dev/null 2>&1; fi\n")

	// 2. Clone or fast-forward the sources at the requested ref.
	b.WriteString("DIR=" + q(remoteDir) + "\n")
	b.WriteString("if [ -d \"$DIR/.git\" ]; then ")
	b.WriteString("git -C \"$DIR\" fetch --depth 1 origin " + q(spec.Ref) + " && ")
	b.WriteString("git -C \"$DIR\" checkout -f FETCH_HEAD; ")
	b.WriteString("else rm -rf \"$DIR\" && git clone --depth 1 --branch " + q(spec.Ref) + " " + q(spec.Repo) + " \"$DIR\"; fi\n")

	// 3. Build the server image with the stealth+QUIC build tags.
	b.WriteString("docker build -f \"$DIR/" + dockerfilePath + "\" --build-arg TAGS=" + q(serverBuildTags) +
		" -t " + q(spec.Image) + " \"$DIR\" >/dev/null\n")

	// 4. Generate ONE keypair on the VPS, shared by every listener below so
	// the server has a single identity across all its transports. PRIV
	// stays in this shell only.
	b.WriteString("KEYS=$(docker run --rm " + q(spec.Image) + " keygen)\n")
	b.WriteString("PRIV=$(printf '%s\\n' \"$KEYS\" | sed -n 's/^private[^:]*: *//p')\n")
	b.WriteString("PUB=$(printf '%s\\n' \"$KEYS\" | sed -n 's/^public[^:]*: *//p')\n")
	b.WriteString("if [ -z \"$PRIV\" ] || [ -z \"$PUB\" ]; then echo 'keygen failed' >&2; exit 1; fi\n")

	// 5. (Re)launch one container per listener, all keyed off the same PRIV.
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

	// 6. Emit only the public key (shared by every listener above).
	b.WriteString("echo \"" + pubMarker + "$PUB\"\n")
	return b.String(), nil
}
