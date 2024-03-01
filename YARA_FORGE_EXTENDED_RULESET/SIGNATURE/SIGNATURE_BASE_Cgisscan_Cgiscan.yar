import "pe"

rule SIGNATURE_BASE_Cgisscan_Cgiscan
{
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "60bd5038-a308-55fd-85bb-2c4183f1c951"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L247-L259"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "338820e4e8e7c943074d5a5bc832458a"
		logic_hash = "5bd856a77c53616cf78d093462f8b7ca5a5fb0924406a02941d86bdb015a1fbc"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"

	condition:
		all of ($s*)
}
