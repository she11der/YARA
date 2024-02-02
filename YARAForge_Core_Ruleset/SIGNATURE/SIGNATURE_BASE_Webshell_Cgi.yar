rule SIGNATURE_BASE_Webshell_Cgi
{
	meta:
		description = "Semi-Auto-generated  - file WebShell.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "b768bb72-64e8-545a-9123-3d5889b58a82"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3960-L3971"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "bc486c2e00b5fc3e4e783557a2441e6f"
		logic_hash = "8908ced96284de6b6d5ae693ba54c49a6333bbe5780d951cbacc91b4dde027df"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "WebShell.cgi"
		$s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"

	condition:
		all of them
}