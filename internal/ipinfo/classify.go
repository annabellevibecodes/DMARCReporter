package ipinfo

import "strings"

// ptrProviders maps reverse-DNS suffixes to human-readable sending-service
// names. Matching is on domain boundaries against the PTR record.
var ptrProviders = map[string]string{
	"google.com":              "Google / Gmail",
	"googlemail.com":          "Google / Gmail",
	"outbound.protection.outlook.com": "Microsoft 365",
	"protection.outlook.com":  "Microsoft 365",
	"outlook.com":             "Microsoft 365",
	"amazonses.com":           "Amazon SES",
	"smtp-out.amazonses.com":  "Amazon SES",
	"sendgrid.net":            "SendGrid",
	"mailgun.net":             "Mailgun",
	"mailgun.org":             "Mailgun",
	"mcsv.net":                "Mailchimp",
	"mcdlv.net":               "Mailchimp",
	"rsgsv.net":               "Mailchimp",
	"sparkpostmail.com":       "SparkPost",
	"mandrillapp.com":         "Mandrill",
	"mktomail.com":            "Marketo",
	"exacttarget.com":         "Salesforce Marketing Cloud",
	"mailjet.com":             "Mailjet",
	"postmarkapp.com":         "Postmark",
	"mtasv.net":               "Postmark",
	"sendinblue.com":          "Brevo (Sendinblue)",
	"sendib.com":              "Brevo (Sendinblue)",
	"zoho.com":                "Zoho Mail",
	"zohomail.com":            "Zoho Mail",
	"yahoodns.net":            "Yahoo",
	"yahoo.com":               "Yahoo",
	"icloud.com":              "Apple iCloud",
	"apple.com":               "Apple",
	"pphosted.com":            "Proofpoint",
	"ppe-hosted.com":          "Proofpoint Essentials",
	"mimecast.com":            "Mimecast",
	"barracudanetworks.com":   "Barracuda",
	"fireeyecloud.com":        "Trellix",
	"mailchannels.net":        "MailChannels",
	"ovh.net":                 "OVH",
	"hetzner.com":             "Hetzner",
	"hetzner.de":              "Hetzner",
	"linode.com":              "Linode/Akamai",
	"digitalocean.com":        "DigitalOcean",
	"vultr.com":               "Vultr",
	"secureserver.net":        "GoDaddy",
	"registeredsite.com":      "Web.com",
	"qq.com":                  "Tencent QQ Mail",
	"163.com":                 "NetEase Mail",
	"infomaniak.ch":           "Infomaniak",
	"protonmail.ch":           "Proton Mail",
	"proton.ch":               "Proton Mail",
	"migadu.com":              "Migadu",
	"fastmail.com":            "Fastmail",
	"messagingengine.com":     "Fastmail",
	"hornetsecurity.ch":       "Hornet Security",
}

// ProviderFromRDNS returns a friendly sending-service name derived from a
// reverse-DNS hostname, or "" when unknown.
func ProviderFromRDNS(rdns string) string {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rdns)), ".")
	if host == "" {
		return ""
	}
	labels := strings.Split(host, ".")
	// Try progressively shorter suffixes (most-specific match wins).
	for i := 0; i < len(labels)-1; i++ {
		suffix := strings.Join(labels[i:], ".")
		if name, ok := ptrProviders[suffix]; ok {
			return name
		}
	}
	return ""
}
