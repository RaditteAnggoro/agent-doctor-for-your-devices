package discovery

import "testing"

func TestHostAndExecutionRemainDistinct(t *testing.T) {
	cases := []struct {
		f         facts
		env, host string
	}{
		{facts{os: "linux", version: "5.15-microsoft-standard-WSL2"}, "wsl", "windows"},
		{facts{os: "linux", chrome: true, container: true}, "crostini", "chromeos"},
		{facts{os: "linux", container: true}, "container", "unknown"},
		{facts{os: "darwin"}, "native", "darwin"},
	}
	for _, c := range cases {
		e := detect(c.f)
		if e.Type != c.env || e.HostOS != c.host {
			t.Fatalf("%+v", e)
		}
	}
	e := detect(facts{os: "linux", remote: true})
	if !e.Remote || len(e.Limitations) == 0 {
		t.Fatal("remote limitation missing")
	}
}
