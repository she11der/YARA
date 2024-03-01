rule SIGNATURE_BASE_Threatgroup3390_Strings : FILE
{
	meta:
		description = "Threat Group 3390 APT - Strings"
		author = "Florian Roth (Nextron Systems)"
		id = "9a44393b-5220-5376-ba18-2330f4623cd6"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "http://snip.ly/giNB"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_threatgroup_3390.yar#L185-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d1e4889a48f4f9bfcc12237dd44cd8ad9db9918c6a5859de086d1ddc051ff937"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\"cmd\" /c cd /d \"c:\\Windows\\Temp\\\"&copy" ascii
		$s2 = "svchost.exe a -k -r -s -m5 -v1024000 -padmin-windows2014"
		$s3 = "ren *.rar *.zip" fullword ascii
		$s4 = "c:\\temp\\ipcan.exe" fullword ascii
		$s5 = "<%eval(Request.Item(\"admin-na-google123!@#" ascii

	condition:
		1 of them and filesize <30KB
}
