import "pe"

rule SIGNATURE_BASE_CN_GUI_Scanner
{
	meta:
		description = "Detects an unknown GUI scanner tool - CN background"
		author = "Florian Roth (Nextron Systems)"
		id = "ca88d4d3-5d18-5856-874f-e50deceef54f"
		date = "2014-04-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L475-L492"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3c67bbb1911cdaef5e675c56145e1112"
		logic_hash = "f9281277ad7058527699d1f5037bb78be1363c90f38e2e399592c58f0b313bd7"
		score = 65
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "good.txt" fullword ascii
		$s2 = "IP.txt" fullword ascii
		$s3 = "xiaoyuer" fullword ascii
		$s0w = "ssh(" wide
		$s1w = ").exe" fullword wide

	condition:
		all of them
}
