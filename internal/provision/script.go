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
	port := fmt.Sprintf("%d", spec.ServerPort)

	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("export DEBIAN_FRONTEND=noninteractive\n")

	// 0. Fail fast if the target port is already bound by something else
	// (another web server, a leftover container under a different name,
	// etc.) -- otherwise the operator waits through the full apt/git/docker
	// build only to have the final `docker run -p` fail with a much less
	// legible daemon error. ss ships with iproute2, which is present on
	// every stock Ubuntu/Debian image; skip the check silently if it isn't
	// (the docker run step below still catches it, just later).
	b.WriteString("if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | awk '{print $4}' | grep -qE \":" + port + "$\"; then ")
	b.WriteString("echo \"" + portInUseMarker + ": port " + port + " is already in use on this server\" >&2; exit 1; fi\n")

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

	// 4. Generate a keypair on the VPS. PRIV stays in this shell only.
	b.WriteString("KEYS=$(docker run --rm " + q(spec.Image) + " keygen)\n")
	b.WriteString("PRIV=$(printf '%s\\n' \"$KEYS\" | sed -n 's/^private[^:]*: *//p')\n")
	b.WriteString("PUB=$(printf '%s\\n' \"$KEYS\" | sed -n 's/^public[^:]*: *//p')\n")
	b.WriteString("if [ -z \"$PRIV\" ] || [ -z \"$PUB\" ]; then echo 'keygen failed' >&2; exit 1; fi\n")

	// 5. (Re)launch the server container.
	b.WriteString("docker rm -f " + q(spec.Container) + " >/dev/null 2>&1 || true\n")
	b.WriteString("docker run -d --name " + q(spec.Container) + " --restart unless-stopped ")
	b.WriteString("-p " + port + ":" + port + "/tcp -p " + port + ":" + port + "/udp ")
	b.WriteString(q(spec.Image) + " server -listen :" + port +
		" -steal-host " + q(spec.StealHost) + " -priv \"$PRIV\" -sid " + q(sids) + "\n")

	// 6. Emit only the public key.
	b.WriteString("echo \"" + pubMarker + "$PUB\"\n")
	return b.String(), nil
}
