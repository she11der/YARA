import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Panda_Burst
{
	meta:
		description = "Disclosed hacktool set - file Burst.rar"
		author = "Florian Roth (Nextron Systems)"
		id = "e07c66d1-958e-5ad2-9d5b-380d48af8360"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1216-L1229"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ce8e3d95f89fb887d284015ff2953dbdb1f16776"
		logic_hash = "c334019cab377f4d96f5daee6a2f1fa7e24ecc43b3aee1eb76537640fdfd8a97"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http://60.15.124.106:63389/tasksvr." ascii

	condition:
		all of them
}
