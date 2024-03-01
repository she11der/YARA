import "pe"

rule SIGNATURE_BASE_Aspbackdoor_EDIR
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file EDIR.ASP"
		author = "Florian Roth (Nextron Systems)"
		id = "0895091a-b620-5746-8245-d44716ec2bbe"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1788-L1805"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "03367ad891b1580cfc864e8a03850368cbf3e0bb"
		logic_hash = "be7d956333107a57a0fd86c69fc9eabcd3d9daf3f66385c44ba246fc2000dc4d"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "response.write \"<a href='index.asp'>" fullword ascii
		$s3 = "if Request.Cookies(\"password\")=\"" ascii
		$s6 = "whichdir=server.mappath(Request(\"path\"))" fullword ascii
		$s7 = "Set fs = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$s19 = "whichdir=Request(\"path\")" fullword ascii

	condition:
		all of them
}
